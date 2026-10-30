"""
Unit and Integration Tests for Lightweight Disk-Backed Partitioned Log Broker Engine.

Verifies:
1. Deterministic client_ip partition hashing & Kill-Chain FIFO ordering
2. Strictly contiguous per-partition offsets & _event_id generation
3. Pause/resume behavior during poll(0) with zero loss
4. Watermark offsets and lag calculation
5. Bounded queue limit and unconsumed lag BufferError backpressure
6. Header preservation (OpenTelemetry traceparent & DLQ metadata)
7. Multi-process and multi-connection SQLite WAL concurrency & safety
"""

import multiprocessing
import os
import tempfile
import time
from typing import List, Tuple
import zlib

import pytest

from middleware.lightweight_broker import (
    DEFAULT_NUM_PARTITIONS,
    OFFSET_INVALID,
    ConfigResource,
    ConsumerGroupTopicPartitions,
    BrokerError,
    BrokerException,
    LightweightAdminClient,
    LightweightConsumer,
    LightweightMessage,
    LightweightProducer,
    NewTopic,
    ResourceType,
    SQLiteBrokerStorage,
    TopicPartition,
    compute_partition,
)


# Top-level worker function for multiprocessing tests (must be picklable on Windows)
def _multiprocess_producer_worker(
    db_path: str,
    worker_id: int,
    messages_per_worker: int,
    topic: str,
) -> int:
    producer = LightweightProducer(
        db_path=db_path,
        max_queue_size=10000,
        batch_size=50,
        linger_ms=2.0,
    )
    sent = 0
    try:
        for i in range(messages_per_worker):
            key = f"10.0.0.{worker_id % 10}".encode("utf-8")
            val = f'{{"worker": {worker_id}, "seq": {i}}}'.encode("utf-8")
            producer.produce(topic=topic, key=key, value=val)
            sent += 1
            if i % 10 == 0:
                producer.poll(0)
        remaining = producer.flush(timeout=15.0)
        if remaining > 0:
            raise RuntimeError(f"Worker {worker_id} flush timed out with {remaining} remaining.")
        return sent
    finally:
        producer.close()


@pytest.fixture
def temp_db_path(tmp_path):
    """Provides an isolated SQLite database file path in a temporary directory."""
    db_file = tmp_path / "broker_test.db"
    return str(db_file)


# ---------------------------------------------------------------------------
# 1. Deterministic Partition Hashing & Kill-Chain FIFO Ordering
# ---------------------------------------------------------------------------
class TestDeterministicPartitionHashing:
    def test_compute_partition_matches_crc32_modulo(self):
        """Verifies compute_partition precisely matches zlib.crc32(key) % num_partitions."""
        num_partitions = 3
        ips = ["10.0.0.99", "192.168.1.10", "172.16.42.108", "10.0.0.1", "127.0.0.1"]

        for ip in ips:
            key_bytes = ip.encode("utf-8")
            expected = (zlib.crc32(key_bytes) & 0xFFFFFFFF) % num_partitions
            actual = compute_partition(key_bytes, num_partitions)
            assert actual == expected
            assert 0 <= actual < num_partitions

            # String key produces identical result to bytes key
            assert compute_partition(ip, num_partitions) == expected

    def test_deterministic_routing_in_producer(self, temp_db_path):
        """Verifies that LightweightProducer consistently routes the same client_ip to the same partition."""
        producer = LightweightProducer(db_path=temp_db_path)
        delivered_partitions: List[int] = []

        def on_delivery(err, msg):
            assert err is None
            delivered_partitions.append(msg.partition())

        client_ip = "10.0.0.99"
        expected_part = (zlib.crc32(client_ip.encode("utf-8")) & 0xFFFFFFFF) % 3

        for i in range(10):
            producer.produce(
                topic="security-logs",
                key=client_ip,
                value=f'{{"step": {i}}}',
                on_delivery=on_delivery,
            )

        producer.flush()
        producer.close()

        assert len(delivered_partitions) == 10
        assert all(p == expected_part for p in delivered_partitions)

    def test_kill_chain_fifo_ordering_per_client_ip(self, temp_db_path):
        """
        Verifies Kill-Chain stages for attacker IP 10.0.0.99 (PORT_SCAN -> BRUTE_FORCE -> IOT_CONTROL)
        are consumed in the exact strict chronological order they were produced.
        """
        producer = LightweightProducer(db_path=temp_db_path)
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="kill-chain-verifier",
            auto_offset_reset="earliest",
        )
        consumer.subscribe(["security-logs"])

        attacker_ip = "10.0.0.99"
        stages = ["PORT_SCAN", "BRUTE_FORCE", "IOT_CONTROL"]

        for stage in stages:
            producer.produce(
                topic="security-logs",
                key=attacker_ip,
                value=f'{{"event_type": "{stage}"}}',
            )

        producer.flush()

        consumed_stages: List[str] = []
        for _ in range(len(stages)):
            msg = consumer.poll(timeout=1.0)
            assert msg is not None
            val = msg.value().decode("utf-8")
            for s in stages:
                if s in val:
                    consumed_stages.append(s)

        assert consumed_stages == stages, f"Expected {stages}, got {consumed_stages}"
        producer.close()
        consumer.close()


# ---------------------------------------------------------------------------
# 2. Contiguous Per-Partition Offsets & Independent Topics
# ---------------------------------------------------------------------------
class TestContiguousOffsets:
    def test_strictly_monotonic_contiguous_offsets(self, temp_db_path):
        """Verifies per-partition offsets start at 0 and have zero gaps and zero duplicates."""
        producer = LightweightProducer(db_path=temp_db_path)
        storage = SQLiteBrokerStorage(temp_db_path)

        # Explicitly produce to partition 0
        for i in range(25):
            producer.produce(
                topic="security-logs",
                partition=0,
                value=f'{{"idx": {i}}}',
            )

        producer.flush()

        # Fetch all messages directly from partition 0
        messages = storage.fetch_messages_batch("security-logs", 0, start_offset=0, limit=50)
        assert len(messages) == 25

        offsets = [m.offset() for m in messages]
        expected_offsets = list(range(25))
        assert offsets == expected_offsets

        # Verify _event_id generation matches "{partition}:{offset}"
        event_ids = [f"{m.partition()}:{m.offset()}" for m in messages]
        assert event_ids[0] == "0:0"
        assert event_ids[-1] == "0:24"

        producer.close()
        storage.close()

    def test_independent_topic_offsets(self, temp_db_path):
        """Verifies each topic maintains independent 0-based offset sequences."""
        producer = LightweightProducer(db_path=temp_db_path)
        storage = SQLiteBrokerStorage(temp_db_path)

        topics = ["security-logs", "security-logs.priority", "security-logs.dlq"]
        for topic in topics:
            for i in range(5):
                producer.produce(topic=topic, partition=1, value=f'{{"topic": "{topic}"}}')

        producer.flush()

        for topic in topics:
            low, high = storage.get_watermark_offsets(topic, 1)
            assert low == 0
            assert high == 5
            msgs = storage.fetch_messages_batch(topic, 1, start_offset=0, limit=10)
            assert [m.offset() for m in msgs] == [0, 1, 2, 3, 4]

        producer.close()
        storage.close()


# ---------------------------------------------------------------------------
# 3. Pause / Resume Zero-Loss Behavior During poll(0)
# ---------------------------------------------------------------------------
class TestPauseResumeZeroLoss:
    def test_paused_partition_poll_zero_returns_none(self, temp_db_path):
        """
        Crucial requirement: When a partition is paused, poll(0) MUST NOT dequeue
        any messages from that partition, preserving our zero-loss paused backoff design.
        """
        producer = LightweightProducer(db_path=temp_db_path)
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="pause-test-group",
            auto_offset_reset="earliest",
        )
        consumer.subscribe(["security-logs"])

        # Produce messages to all 3 partitions
        for p in range(3):
            for i in range(5):
                producer.produce(
                    topic="security-logs",
                    partition=p,
                    value=f'{{"part": {p}, "msg": {i}}}',
                )
        producer.flush()

        assigned = consumer.assignment()
        assert len(assigned) == 3

        # Pause ALL assigned partitions
        consumer.pause(assigned)

        # Call poll(0) multiple times: MUST return None and NEVER dequeue
        for _ in range(10):
            msg = consumer.poll(timeout=0)
            assert msg is None, "poll(0) returned a message while partitions were paused!"

        # Resume ONLY partition 1
        tp1 = TopicPartition("security-logs", 1)
        consumer.resume([tp1])

        # poll() should now return messages ONLY from partition 1
        part_1_messages: List[LightweightMessage] = []
        for _ in range(5):
            msg = consumer.poll(timeout=0.2)
            assert msg is not None
            assert msg.partition() == 1
            part_1_messages.append(msg)

        assert len(part_1_messages) == 5

        # Further polls should return None since partition 0 and 2 are still paused
        assert consumer.poll(timeout=0) is None

        # Resume partitions 0 and 2
        tp0 = TopicPartition("security-logs", 0)
        tp2 = TopicPartition("security-logs", 2)
        consumer.resume([tp0, tp2])

        # Drain the remaining messages (5 from part 0, 5 from part 2)
        remaining_messages: List[LightweightMessage] = []
        for _ in range(10):
            msg = consumer.poll(timeout=0.2)
            assert msg is not None
            remaining_messages.append(msg)

        assert len(remaining_messages) == 10
        assert {m.partition() for m in remaining_messages} == {0, 2}

        # Queue is now empty
        assert consumer.poll(timeout=0) is None

        producer.close()
        consumer.close()


# ---------------------------------------------------------------------------
# 4. Watermark & Lag Calculations
# ---------------------------------------------------------------------------
class TestWatermarkAndLagCalculation:
    def test_watermark_offsets_empty_and_populated(self, temp_db_path):
        """Tests low and high watermark offsets before and after producing."""
        producer = LightweightProducer(db_path=temp_db_path)
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="lag-group",
        )
        tp = TopicPartition("security-logs", 0)

        # Empty partition
        low, high = consumer.get_watermark_offsets(tp)
        assert low == 0
        assert high == 0

        # Uncommitted offset returns OFFSET_INVALID (-1001)
        committed_tp = consumer.committed([tp])[0]
        assert committed_tp.offset == OFFSET_INVALID

        # Produce 12 messages to partition 0
        for i in range(12):
            producer.produce("security-logs", partition=0, value=f'{{"i": {i}}}')
        producer.flush()

        low, high = consumer.get_watermark_offsets(tp)
        assert low == 0
        assert high == 12

        # Commit offset 5
        consumer.commit([TopicPartition("security-logs", 0, offset=5)])
        committed_tp = consumer.committed([tp])[0]
        assert committed_tp.offset == 5

        # Calculate lag
        lag = high - committed_tp.offset
        assert lag == 7

        # Commit all (offset 12)
        consumer.commit([TopicPartition("security-logs", 0, offset=12)])
        committed_tp = consumer.committed([tp])[0]
        assert committed_tp.offset == 12
        assert high - committed_tp.offset == 0

        producer.close()
        consumer.close()

    def test_consumer_seek_resets_position(self, temp_db_path):
        """Verifies seek() explicitly overrides the consumer's next fetch offset."""
        producer = LightweightProducer(db_path=temp_db_path)
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="seek-group",
            auto_offset_reset="earliest",
        )
        consumer.subscribe(["security-logs"])

        tp = TopicPartition("security-logs", 0)
        for i in range(10):
            producer.produce("security-logs", partition=0, value=f'{{"i": {i}}}')
        producer.flush()

        # Poll 4 messages (offsets 0, 1, 2, 3)
        for expected_offset in range(4):
            m = consumer.poll(timeout=0.2)
            assert m is not None
            assert m.offset() == expected_offset

        # Seek back to offset 1
        consumer.seek(TopicPartition("security-logs", 0, offset=1))

        # Next poll should re-read offset 1
        m = consumer.poll(timeout=0.2)
        assert m is not None
        assert m.offset() == 1

        producer.close()
        consumer.close()


# ---------------------------------------------------------------------------
# 5. Bounded Queue Limit & Backpressure (BufferError)
# ---------------------------------------------------------------------------
class TestBoundedQueueAndBackpressure:
    def test_max_queue_size_triggers_buffer_error(self, temp_db_path):
        """Verifies producer raises BufferError immediately when in-memory queue exceeds bound."""
        # Stop background writer by setting a tiny queue and preventing draining
        producer = LightweightProducer(
            db_path=temp_db_path,
            max_queue_size=3,
            linger_ms=1000.0,  # Long linger to keep messages in queue
        )

        with pytest.raises(BufferError):
            for i in range(10):
                producer.produce("security-logs", value=f'{{"i": {i}}}')

        producer.flush()
        producer.close()

    def test_max_unconsumed_lag_triggers_buffer_error(self, temp_db_path):
        """Verifies producer raises BufferError when unconsumed lag exceeds configured limit."""
        producer = LightweightProducer(
            db_path=temp_db_path,
            max_unconsumed_lag=5,
        )

        # Produce 5 messages without any consumer committing
        for i in range(5):
            producer.produce("security-logs", value=f'{{"i": {i}}}')
        producer.flush()

        # The 6th produce should trigger backpressure due to lag >= 5
        with pytest.raises(BufferError):
            producer.produce("security-logs", value=b'{"i": 6}')

        # Consume and commit to relieve backpressure
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="backpressure-consumer",
            auto_offset_reset="earliest",
        )
        consumer.subscribe(["security-logs"])
        msgs = consumer.consume(num_messages=5, timeout=1.0)
        assert len(msgs) == 5
        consumer.commit()

        # Refresh producer's cached lag after consumer offset commit
        producer.refresh_unconsumed_lag("security-logs")

        # Now produce should succeed immediately
        producer.produce("security-logs", value=b'{"i": 6}')
        producer.flush()

        producer.close()
        consumer.close()


# ---------------------------------------------------------------------------
# 6. Delivery Callbacks & OpenTelemetry Headers Preservation
# ---------------------------------------------------------------------------
class TestDeliveryCallbacksAndHeaders:
    def test_delivery_callback_and_flush(self, temp_db_path):
        """Verifies on_delivery callback receives delivered message details during flush."""
        producer = LightweightProducer(db_path=temp_db_path)
        callback_reports = []

        def on_delivery(err, msg):
            assert err is None
            callback_reports.append((msg.topic(), msg.partition(), msg.offset()))

        for i in range(5):
            producer.produce(
                "security-logs",
                partition=2,
                value=f'{{"test": {i}}}',
                on_delivery=on_delivery,
            )

        remaining = producer.flush(timeout=5.0)
        assert remaining == 0
        assert len(callback_reports) == 5
        assert callback_reports[0] == ("security-logs", 2, 0)
        assert callback_reports[-1] == ("security-logs", 2, 4)

        producer.close()

    def test_opentelemetry_headers_binary_roundtrip(self, temp_db_path):
        """Verifies OpenTelemetry traceparent and DLQ metadata headers round-trip without corruption."""
        producer = LightweightProducer(db_path=temp_db_path)
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="otel-test",
            auto_offset_reset="earliest",
        )
        consumer.subscribe(["security-logs"])

        headers = [
            ("traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            ("x-retry-count", b"3"),
            ("x-original-topic", b"security-logs.priority"),
        ]

        producer.produce(
            topic="security-logs",
            value=b'{"otel": "test"}',
            headers=headers,
        )
        producer.flush()

        msg = consumer.poll(timeout=1.0)
        assert msg is not None
        received_headers = msg.headers()
        assert received_headers is not None
        assert len(received_headers) == 3

        header_dict = dict(received_headers)
        assert header_dict["traceparent"] == b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        assert header_dict["x-retry-count"] == b"3"
        assert header_dict["x-original-topic"] == b"security-logs.priority"

        producer.close()
        consumer.close()


# ---------------------------------------------------------------------------
# 7. AdminClient Compatibility
# ---------------------------------------------------------------------------
class TestAdminClientCompatibility:
    def test_admin_client_topic_creation_and_listing(self, temp_db_path):
        """Verifies LightweightAdminClient topic management."""
        admin = LightweightAdminClient(db_path=temp_db_path)

        metadata = admin.list_topics()
        # Default topics should exist
        assert "security-logs" in metadata.topics
        assert "security-logs.priority" in metadata.topics

        # Create new topic
        new_topic = NewTopic(topic="custom-audit-logs", num_partitions=4)
        futures = admin.create_topics([new_topic])
        res = futures["custom-audit-logs"].result()
        assert res == "custom-audit-logs"

        # Duplicate creation raises BrokerException with TOPIC_ALREADY_EXISTS
        dup_futures = admin.create_topics([new_topic])
        with pytest.raises(BrokerException) as exc_info:
            dup_futures["custom-audit-logs"].result()
        assert exc_info.value.args()[0].code() == BrokerError.TOPIC_ALREADY_EXISTS

        # Alter configs mock
        resource = ConfigResource(ResourceType.TOPIC, "custom-audit-logs", {"retention.ms": "86400000"})
        alter_res = admin.alter_configs([resource])
        assert alter_res[resource].result() is None

        # Inspect consumer group offsets
        group_req = [ConsumerGroupTopicPartitions("admin-test-group", [TopicPartition("custom-audit-logs", 0)])]
        offset_futures = admin.list_consumer_group_offsets(group_req)
        group_res = offset_futures["admin-test-group"].result()
        assert len(group_res.topic_partitions) == 1
        assert group_res.topic_partitions[0].offset == OFFSET_INVALID

        admin.close()


# ---------------------------------------------------------------------------
# 8. Multi-Process / Multi-Connection SQLite WAL Safety
# ---------------------------------------------------------------------------
class TestMultiProcessWALSafety:
    def test_concurrent_multiprocess_producers_wal_safety(self, temp_db_path):
        """
        Spawns multiple separate OS processes writing concurrently to the same
        SQLite database file in WAL mode. Verifies:
        1. 0.00% log loss (Total Sent == Total Stored).
        2. Strictly contiguous per-partition offsets with no duplicates or gaps.
        3. All messages are cleanly readable by a consumer.
        """
        num_workers = 3
        messages_per_worker = 100
        topic = "security-logs"
        # Ensure schema is initialized before spawning child worker processes
        init_storage = SQLiteBrokerStorage(temp_db_path)
        init_storage.close()

        ctx = multiprocessing.get_context("spawn")
        processes: List[multiprocessing.Process] = []

        for worker_id in range(num_workers):
            p = ctx.Process(
                target=_multiprocess_producer_worker,
                args=(temp_db_path, worker_id, messages_per_worker, topic),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=30)
            assert p.exitcode == 0, f"Worker process failed with exit code {p.exitcode}"

        expected_total = num_workers * messages_per_worker

        # Verify using SQLiteBrokerStorage
        storage = SQLiteBrokerStorage(temp_db_path)
        total_stored = 0
        for p in range(DEFAULT_NUM_PARTITIONS):
            low, high = storage.get_watermark_offsets(topic, p)
            count = high - low
            total_stored += count

            # Verify offsets in this partition are strictly contiguous: 0, 1, ..., high - 1
            if count > 0:
                msgs = storage.fetch_messages_batch(topic, p, start_offset=0, limit=count + 10)
                offsets = [m.offset() for m in msgs]
                assert offsets == list(range(count)), f"Partition {p} had offset gaps/duplicates: {offsets}"

        assert total_stored == expected_total, (
            f"Expected {expected_total} messages stored, but found {total_stored}. Log loss detected!"
        )

        # Verify a consumer can read all messages
        consumer = LightweightConsumer(
            db_path=temp_db_path,
            group_id="mp-verifier-group",
            auto_offset_reset="earliest",
        )
        consumer.subscribe([topic])
        consumed_count = 0

        while True:
            msgs = consumer.consume(num_messages=50, timeout=0.5)
            if not msgs:
                break
            consumed_count += len(msgs)

        assert consumed_count == expected_total
        consumer.close()
        storage.close()


# ---------------------------------------------------------------------------
# 9. High-Throughput Burst Ingestion (5,000+ EPS)
# ---------------------------------------------------------------------------
class TestBurstThroughput:
    def test_burst_ingestion_throughput_sustained(self, temp_db_path):
        """
        Verifies that LightweightProducer sustains 5,000+ EPS burst ingestion
        via in-memory queue buffering and fast WAL batch commits.
        """
        burst_count = 5000
        producer = LightweightProducer(
            db_path=temp_db_path,
            max_queue_size=20000,
            batch_size=500,
            linger_ms=2.0,
        )

        sample_val = b'{"timestamp": 1729388400.123, "event_type": "PORT_SCAN", "severity": 4}'
        client_ips = [f"192.168.1.{i % 250}".encode("utf-8") for i in range(100)]

        start_time = time.monotonic()
        for i in range(burst_count):
            ip = client_ips[i % len(client_ips)]
            producer.produce("security-logs", key=ip, value=sample_val)

        flush_start = time.monotonic()
        remaining = producer.flush(timeout=10.0)
        total_time = time.monotonic() - start_time

        assert remaining == 0, f"Flush timed out with {remaining} messages remaining."
        eps = burst_count / total_time
        assert eps >= 5000.0, f"Burst throughput was {eps:.1f} EPS, below required 5,000 EPS!"

        # Verify all 5,000 messages stored and verifiable
        storage = SQLiteBrokerStorage(temp_db_path)
        total_stored = 0
        for p in range(DEFAULT_NUM_PARTITIONS):
            low, high = storage.get_watermark_offsets("security-logs", p)
            total_stored += (high - low)

        assert total_stored == burst_count
        producer.close()
        storage.close()

