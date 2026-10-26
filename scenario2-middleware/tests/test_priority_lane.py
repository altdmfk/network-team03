"""
tests/test_priority_lane.py
===========================
Comprehensive Test Suite for High-Priority Topic Routing and Weighted Draining:
1. Routing rules:
   - HONEYTOKEN_ACCESS and severity <= 2 route to `security-logs.priority`.
   - severity > 2 routes to `security-logs`.
   - Configurable PRIORITY_EVENT_TYPES and PRIORITY_MAX_SEVERITY.
   - Preserves client_ip partition key across both topics.
2. Weighted dual-lane draining in BrokerBatchPoller:
   - Priority preference: priority consumed first.
   - Starvation prevention: standard traffic guaranteed reserved share (e.g. 30%).
   - Slack absorption: either lane can absorb unused quota when the other is empty.
   - Single-item allocation preference.
   - Linger window micro-batch accumulation across both topics.
3. Multi-topic offset commits in ExplicitOffsetCommitter:
   - Per-(topic, partition) offset computation across standard and priority topics.
   - Multi-topic atomic commit call via consumer.commit(batch_offsets).
4. Deterministic latency assertion with injected clocks:
   - Simulates 5,000 scan logs + 1 HONEYTOKEN_ACCESS alert.
   - Demonstrates Honeytoken delivered in batch 1 within < 2.0s budget (vs 10s under FIFO).
   - Verifies 5,001 logs delivered with zero log loss.
5. Metrics per-lane lag and EPS:
   - /metrics exposes priority_queue_lag, standard_queue_lag, priority_outbound_eps, standard_outbound_eps.
   - Backward compatibility for existing fields.
6. Graylog Kill-Chain per-lane verification and GELF _broker_topic field:
   - GelfTransformer injects _broker_topic.
   - MockGraylogState validates per-lane ordering and reports cross-lane as "best effort".
"""

import copy
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from middleware.lightweight_broker import LightweightMessage as Message, TopicPartition
from fastapi.testclient import TestClient

from config import (
    HONEYTOKEN_LATENCY_BUDGET,
    BROKER_CONSUMER_GROUP,
    BROKER_PARTITIONS,
    BROKER_PRIORITY_TOPIC,
    BROKER_TOPIC,
    MAX_LOGS_PER_SEC,
    PRIORITY_EVENT_TYPES,
    PRIORITY_MAX_SEVERITY,
    STANDARD_RESERVED_SHARE,
    PipelineSettings,
    load_settings,
)
import ingestor
from metrics_store import SharedMetricsStore
from middleware.batch_poller import BrokerBatchPoller
from middleware.offset_committer import ExplicitOffsetCommitter
from middleware.gelf_transformer import GelfTransformer, transform_to_gelf
from middleware.rate_limiter import TokenBucketRateLimiter
from mock_graylog_server import MockGraylogState


# ---------------------------------------------------------------------------
# Test Helpers & Fake Broker Message
# ---------------------------------------------------------------------------

class FakeBrokerMessage:
    """Mock Message for poller and committer testing."""

    def __init__(
        self,
        topic: str,
        partition: int,
        offset: int,
        value: bytes,
        key: Optional[bytes] = None,
        timestamp_ms: int = 0,
        err: Any = None,
    ):
        self._topic = topic
        self._partition = partition
        self._offset = offset
        self._value = value
        self._key = key
        self._timestamp_ms = timestamp_ms
        self._error = err

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def value(self) -> Optional[bytes]:
        return self._value

    def key(self) -> Optional[bytes]:
        return self._key

    def timestamp(self) -> tuple:
        return (1, self._timestamp_ms)

    def error(self) -> Any:
        return self._error


class FakeConsumer:
    """Simulates broker Consumer with dual-topic message streams."""

    def __init__(
        self,
        messages: Optional[List[FakeBrokerMessage]] = None,
        priority_messages: Optional[List[FakeBrokerMessage]] = None,
        standard_messages: Optional[List[FakeBrokerMessage]] = None,
    ):
        self._priority_msgs = list(priority_messages or [])
        self._standard_msgs = list(standard_messages or [])
        if messages:
            for m in messages:
                if m.topic() == "security-logs.priority":
                    self._priority_msgs.append(m)
                else:
                    self._standard_msgs.append(m)
        self.subscribed_topics = []
        self.committed_offsets = None
        self.commit_count = 0

    def subscribe(self, topics: List[str], **kwargs):
        self.subscribed_topics = list(topics)

    def poll(self, timeout: float = 0.1) -> Optional[FakeBrokerMessage]:
        if self._priority_msgs:
            return self._priority_msgs.pop(0)
        if self._standard_msgs:
            return self._standard_msgs.pop(0)
        return None

    def consume(self, num_messages: int = 1, timeout: float = 0.1) -> List[FakeBrokerMessage]:
        res = []
        for _ in range(num_messages):
            m = self.poll(timeout=timeout)
            if m is not None:
                res.append(m)
            else:
                break
        return res

    def commit(self, offsets=None, asynchronous=False):
        self.committed_offsets = offsets
        self.commit_count += 1
        return offsets

    def assign(self, partitions):
        pass

    def pause(self, partitions):
        pass

    def resume(self, partitions):
        pass

    def close(self):
        pass


# ---------------------------------------------------------------------------
# 1. Routing Rules & Config Tests
# ---------------------------------------------------------------------------

class TestPriorityRoutingRules:
    """Verifies that the Ingestor correctly classifies and routes events."""

    def test_honeytoken_access_routes_to_priority_topic(self):
        event = {
            "client_ip": "192.168.1.100",
            "event_type": "HONEYTOKEN_ACCESS",
            "target_resource": "/admin/keys",
            "status_code": 403,
            "severity": 4,
            "raw_payload": {"msg": "trap triggered"},
        }
        assert ingestor.is_priority_event(event) is True
        assert ingestor.route_event_topic(event) == BROKER_PRIORITY_TOPIC

    def test_low_severity_events_route_to_priority_topic(self):
        # severity <= 2 (Emergency=0, Alert=1, Critical=2)
        for sev in [0, 1, 2]:
            event = {
                "client_ip": "10.0.0.5",
                "event_type": "PORT_SCAN",
                "target_resource": "/api",
                "status_code": 200,
                "severity": sev,
                "raw_payload": "test",
            }
            assert ingestor.is_priority_event(event) is True
            assert ingestor.route_event_topic(event) == BROKER_PRIORITY_TOPIC

    def test_standard_severity_events_route_to_standard_topic(self):
        # severity > 2 (Error=3, Warning=4, Notice=5, Info=6, Debug=7)
        for sev in [3, 4, 5, 6, 7]:
            event = {
                "client_ip": "10.0.0.5",
                "event_type": "PORT_SCAN",
                "target_resource": "/api",
                "status_code": 200,
                "severity": sev,
                "raw_payload": "test",
            }
            assert ingestor.is_priority_event(event) is False
            assert ingestor.route_event_topic(event) == BROKER_TOPIC

    def test_custom_priority_event_types_and_max_severity(self):
        # Test override of priority event types
        custom_types = ["RANSOMWARE_ENCRYPT", "DATA_EXFIL"]
        event1 = {"event_type": "RANSOMWARE_ENCRYPT", "severity": 5}
        event2 = {"event_type": "PORT_SCAN", "severity": 1}
        event3 = {"event_type": "PORT_SCAN", "severity": 4}

        assert ingestor.is_priority_event(event1, priority_types=custom_types) is True
        assert ingestor.is_priority_event(event2, priority_types=custom_types) is True
        assert ingestor.is_priority_event(event3, priority_types=custom_types) is False

        # Test override of priority max severity to 1
        assert ingestor.is_priority_event({"event_type": "SCAN", "severity": 2}, max_severity=1) is False
        assert ingestor.is_priority_event({"event_type": "SCAN", "severity": 1}, max_severity=1) is True

    def test_client_ip_partition_key_preservation(self):
        """Ensures client_ip is strictly preserved as the partition key on produce."""
        mock_producer = MagicMock()
        mock_producer.__len__.return_value = 0

        middleware = ingestor.WalLogBufferingMiddleware(
            metrics_store=MagicMock()
        )
        middleware.producer = mock_producer

        # Enqueue priority event
        ht_event = ingestor.SecurityLogEvent(
            client_ip="198.51.100.42",
            event_type="HONEYTOKEN_ACCESS",
            target_resource="/admin",
            status_code=403,
            severity=1,
            raw_payload={"foo": "bar"},
        )
        middleware.enqueue_event(ht_event)

        # Verify produce was called with topic=security-logs.priority and key=b"198.51.100.42"
        mock_producer.produce.assert_called_once()
        call_kwargs = mock_producer.produce.call_args[1]
        assert call_kwargs["topic"] == "security-logs.priority"
        assert call_kwargs["key"] == b"198.51.100.42"

    def test_settings_validation_rejects_invalid_weights(self):
        """Bounds validation: standard_reserved_share must be strictly in (0.0, 1.0)."""
        with pytest.raises(Exception):
            PipelineSettings(standard_reserved_share=0.0)

        with pytest.raises(Exception):
            PipelineSettings(standard_reserved_share=1.0)

        with pytest.raises(Exception):
            PipelineSettings(standard_reserved_share=1.5)

        with pytest.raises(Exception):
            PipelineSettings(priority_weight=0.0)

        with pytest.raises(Exception):
            PipelineSettings(standard_weight=-0.5)


# ---------------------------------------------------------------------------
# 2. Weighted Dual-Lane Draining Tests in BrokerBatchPoller
# ---------------------------------------------------------------------------

class TestWeightedDualLaneDraining:
    """Verifies priority preferred, starvation-free weighted draining."""

    def test_poller_subscribes_to_both_topics(self):
        consumer = FakeConsumer()
        poller = BrokerBatchPoller(
            batch_size=100,
            linger_ms=100,
            priority_topic="security-logs.priority",
            standard_topic="security-logs",
        )
        poller.subscribe(consumer)
        assert set(consumer.subscribed_topics) == {"security-logs.priority", "security-logs"}

    def test_weighted_allocation_guarantees_standard_share(self):
        """Under flood of both priority and standard logs, standard traffic gets reserved share."""
        poller = BrokerBatchPoller(
            batch_size=100,
            linger_ms=10,
            standard_reserved_share=0.3,
        )

        # Target 100 logs, 500 priority available, 500 standard available
        p_count, s_count = poller.compute_weighted_allocation(
            target_count=100,
            available_priority=500,
            available_standard=500,
        )
        assert s_count == 30  # 30% reserved
        assert p_count == 70  # 70% priority
        assert p_count + s_count == 100

    def test_weighted_allocation_slack_absorption_priority_fills_when_standard_empty(self):
        """When standard lane is empty, priority can take 100% of the batch."""
        poller = BrokerBatchPoller(
            batch_size=100,
            linger_ms=10,
            standard_reserved_share=0.3,
        )

        p_count, s_count = poller.compute_weighted_allocation(
            target_count=100,
            available_priority=200,
            available_standard=0,
        )
        assert s_count == 0
        assert p_count == 100

    def test_weighted_allocation_slack_absorption_standard_fills_when_priority_empty(self):
        """When priority lane is empty, standard can take 100% of the batch."""
        poller = BrokerBatchPoller(
            batch_size=100,
            linger_ms=10,
            standard_reserved_share=0.3,
        )

        p_count, s_count = poller.compute_weighted_allocation(
            target_count=100,
            available_priority=0,
            available_standard=200,
        )
        assert p_count == 0
        assert s_count == 100

    def test_weighted_allocation_single_item_prefers_priority(self):
        """When target_count == 1 and both lanes have messages, priority is preferred."""
        poller = BrokerBatchPoller(batch_size=100, linger_ms=10, standard_reserved_share=0.3)
        p_count, s_count = poller.compute_weighted_allocation(
            target_count=1,
            available_priority=10,
            available_standard=10,
        )
        assert p_count == 1
        assert s_count == 0

    def test_poll_batch_interleaves_prioritizing_honeytoken_over_backlog(self):
        """
        Simulates 100 scan logs polled first into standard queue, then 1 honeytoken log
        polled into priority queue. The poller must emit the honeytoken in the first batch.
        """
        messages = []
        # 100 standard scan logs
        for i in range(100):
            messages.append(
                FakeBrokerMessage(
                    topic="security-logs",
                    partition=0,
                    offset=i,
                    value=json.dumps({"event_type": "SCAN", "seq": i}).encode("utf-8"),
                )
            )
        # 1 priority honeytoken log
        messages.append(
            FakeBrokerMessage(
                topic="security-logs.priority",
                partition=0,
                offset=0,
                value=json.dumps({"event_type": "HONEYTOKEN_ACCESS"}).encode("utf-8"),
            )
        )

        consumer = FakeConsumer(messages)
        poller = BrokerBatchPoller(
            batch_size=10,
            linger_ms=10,
            standard_reserved_share=0.3,
            priority_topic="security-logs.priority",
            standard_topic="security-logs",
        )

        # Batch 1: target 10. Poller reads available messages: priority has 1, standard has 100.
        # Standard reserved share = 3. Priority takes min(available_p, 7) = 1.
        # Standard takes remaining 9.
        batch1, _ = poller.poll_batch(consumer)
        assert len(batch1) == 10
        event_types = [json.loads(m.value().decode())["event_type"] for m in batch1]
        assert "HONEYTOKEN_ACCESS" in event_types
        # Honeytoken alert was prioritized and included in Batch 1!
        assert event_types[0] == "HONEYTOKEN_ACCESS"


# ---------------------------------------------------------------------------
# 3. Multi-Topic Offset Commit Correctness Tests
# ---------------------------------------------------------------------------

class TestMultiTopicOffsetCommits:
    """Verifies that ExplicitOffsetCommitter handles multiple topics correctly."""

    def test_compute_batch_offsets_across_multiple_topics_and_partitions(self):
        committer = ExplicitOffsetCommitter()

        # Batch containing messages from both security-logs and security-logs.priority
        messages = [
            FakeBrokerMessage(topic="security-logs", partition=0, offset=10, value=b"a"),
            FakeBrokerMessage(topic="security-logs", partition=0, offset=11, value=b"b"),
            FakeBrokerMessage(topic="security-logs", partition=1, offset=5, value=b"c"),
            FakeBrokerMessage(topic="security-logs.priority", partition=0, offset=0, value=b"p0"),
            FakeBrokerMessage(topic="security-logs.priority", partition=2, offset=42, value=b"p2"),
        ]

        batch_offsets = committer.compute_batch_offsets(messages)

        # Must have exactly 4 (topic, partition) entries
        assert len(batch_offsets) == 4
        expected = {
            ("security-logs", 0): 12,          # 11 + 1
            ("security-logs", 1): 6,           # 5 + 1
            ("security-logs.priority", 0): 1,   # 0 + 1
            ("security-logs.priority", 2): 43,  # 42 + 1
        }
        for tp in batch_offsets:
            assert expected[(tp.topic, tp.partition)] == tp.offset

    def test_commit_batch_offsets_submits_all_topic_partitions(self):
        committer = ExplicitOffsetCommitter()
        consumer = FakeConsumer()

        messages = [
            FakeBrokerMessage(topic="security-logs", partition=0, offset=100, value=b"1"),
            FakeBrokerMessage(topic="security-logs.priority", partition=0, offset=50, value=b"2"),
        ]

        committed = committer.commit_batch_offsets(consumer, messages)
        assert committed is not None
        assert len(committed) == 2
        assert consumer.commit_count == 1
        # Offsets passed to consumer.commit:
        committed_tuples = {(tp.topic, tp.partition, tp.offset) for tp in consumer.committed_offsets}
        assert ("security-logs", 0, 101) in committed_tuples
        assert ("security-logs.priority", 0, 51) in committed_tuples


# ---------------------------------------------------------------------------
# 4. Deterministic Latency Assertion with Injected Clocks
# ---------------------------------------------------------------------------

class TestDeterministicLatencyWithInjectedClocks:
    """
    Deterministic unit test proving the core thesis:
    5,000 standard scan logs + 1 HONEYTOKEN_ACCESS.
    Without priority lane: Honeytoken waits ~10 seconds at 500 EPS.
    With priority lane: Honeytoken is delivered in Batch 1 within < 2.0s latency budget.
    """

    def test_honeytoken_latency_under_backlog_with_injected_clock(self):
        # Setup fake messages: 5,000 scan logs on standard topic, 1 honeytoken on priority topic
        total_scan_logs = 5000
        standard_msgs = [
            FakeBrokerMessage(
                topic="security-logs",
                partition=i % 3,
                offset=i,
                value=json.dumps({"event_type": "PORT_SCAN", "id": i}).encode(),
            )
            for i in range(total_scan_logs)
        ]
        priority_msg = FakeBrokerMessage(
            topic="security-logs.priority",
            partition=0,
            offset=0,
            value=json.dumps({"event_type": "HONEYTOKEN_ACCESS", "id": "ht-01"}).encode(),
        )

        # In a realistic arrival sequence, the 5,000 logs arrive first, then the honeytoken
        all_incoming = list(standard_msgs) + [priority_msg]
        consumer = FakeConsumer(all_incoming)

        # Injected clock simulation
        sim_time = [1000.0]

        def fake_monotonic() -> float:
            return sim_time[0]

        def fake_sleep(duration: float) -> None:
            sim_time[0] += duration

        # Poller configured with batch_size=100, rate_limit=500 EPS
        batch_size = 100
        poller = BrokerBatchPoller(
            batch_size=batch_size,
            linger_ms=10,
            standard_reserved_share=0.3,
            priority_topic="security-logs.priority",
            standard_topic="security-logs",
        )

        # Track honeytoken delivery time
        honeytoken_injected_at = sim_time[0]
        honeytoken_delivered_at = None

        delivered_messages = []
        committer = ExplicitOffsetCommitter()

        # Drain loop
        batches_processed = 0
        while len(delivered_messages) < total_scan_logs + 1:
            batch, _ = poller.poll_batch(consumer)
            if not batch:
                break

            batches_processed += 1
            # Simulate processing time + token bucket rate limiting (500 logs/sec = 0.2s per 100-log batch)
            batch_duration = len(batch) / float(MAX_LOGS_PER_SEC)
            fake_sleep(batch_duration)

            for m in batch:
                payload = json.loads(m.value().decode())
                if payload["event_type"] == "HONEYTOKEN_ACCESS":
                    honeytoken_delivered_at = sim_time[0]
                delivered_messages.append(m)

            # Confirm offset commit after delivery
            committer.commit_batch_offsets(consumer, batch)

        # Assertions
        assert len(delivered_messages) == 5001, "Zero-loss invariant violated: not all messages delivered!"
        assert honeytoken_delivered_at is not None, "Honeytoken alert was never delivered!"

        honeytoken_latency = honeytoken_delivered_at - honeytoken_injected_at

        # Verify honeytoken was delivered in Batch 1!
        # With 100-log batch size at 500 EPS, Batch 1 finishes in 0.20s.
        assert honeytoken_latency <= HONEYTOKEN_LATENCY_BUDGET, (
            f"Honeytoken latency {honeytoken_latency:.3f}s exceeded budget {HONEYTOKEN_LATENCY_BUDGET}s"
        )
        assert honeytoken_latency == pytest.approx(0.2, abs=0.01)

        # Contrast with standard FIFO: without priority, 5,000 logs at 500 EPS would take 10.0 seconds!
        fifo_expected_latency = 5000.0 / float(MAX_LOGS_PER_SEC)
        assert fifo_expected_latency == 10.0
        assert honeytoken_latency < fifo_expected_latency / 5.0, (
            f"Priority lane failed to significantly accelerate alert: {honeytoken_latency}s vs {fifo_expected_latency}s"
        )


# ---------------------------------------------------------------------------
# 5. Metrics & Dual-Lane Lag/EPS Tests
# ---------------------------------------------------------------------------

class TestDualLaneMetricsAndTelemetry:
    """Verifies per-lane lag and outbound EPS exposed on /metrics."""

    def test_shared_metrics_store_tracks_per_lane_outbound_eps(self, tmp_path):
        db_file = str(tmp_path / "metrics_test.db")
        with SharedMetricsStore(db_file) as store:
            # Increment 70 priority and 30 standard
            store.increment_forwarded(priority_count=70, standard_count=30, flush=True)

            snap = store.read_snapshot()
            assert snap["total_forwarded_to_graylog"] == 100
            # Both per-lane outbound EPS fields are present
            assert "priority_outbound_eps" in snap
            assert "standard_outbound_eps" in snap
            assert "outbound_eps" in snap

    def test_get_metrics_endpoint_exposes_lane_breakdowns(self, tmp_path, monkeypatch):
        db_file = str(tmp_path / "metrics_endpoint.db")
        with SharedMetricsStore(db_file) as store:
            store.increment_received(100, flush=True)
            store.increment_forwarded(priority_count=20, standard_count=40, flush=True)

            middleware = ingestor.WalLogBufferingMiddleware(store)
            mock_producer = MagicMock()
            mock_producer.__len__.return_value = 0
            middleware.producer = mock_producer

            mock_admin = MagicMock()
            future_mock = MagicMock()
            group_result_mock = MagicMock()
            group_result_mock.topic_partitions = [
                TopicPartition("security-logs", 0, 10),
                TopicPartition("security-logs", 1, 0),
                TopicPartition("security-logs", 2, 0),
                TopicPartition("security-logs.priority", 0, 5),
                TopicPartition("security-logs.priority", 1, 0),
                TopicPartition("security-logs.priority", 2, 0),
            ]
            future_mock.result.return_value = group_result_mock
            mock_admin.list_consumer_group_offsets.return_value = {
                BROKER_CONSUMER_GROUP: future_mock
            }

            def fake_watermark(tp, **kwargs):
                if tp.topic == "security-logs":
                    if tp.partition == 0:
                        return (0, 20)  # lag = 20 - 10 = 10
                    return (0, 0)
                if tp.topic == "security-logs.priority":
                    if tp.partition == 0:
                        return (0, 8)   # lag = 8 - 5 = 3
                    return (0, 0)
                return (0, 0)

            mock_watermark = MagicMock()
            mock_watermark.get_watermark_offsets.side_effect = fake_watermark

            middleware.admin_client = mock_admin
            middleware._watermark_consumer = mock_watermark

            monkeypatch.setattr(ingestor, "metrics_store", store)
            monkeypatch.setattr(ingestor, "wal_middleware", middleware)
            monkeypatch.setattr(middleware, "start", lambda: None)
            monkeypatch.setattr(middleware, "stop", lambda: None)

            with TestClient(ingestor.app) as client:
                resp = client.get("/metrics")
                assert resp.status_code == 200
                data = resp.json()

                # Verify per-lane lag fields exist
                assert "priority_queue_lag" in data
                assert "standard_queue_lag" in data
                assert data["priority_queue_lag"] == 3
                assert data["standard_queue_lag"] == 10

                # Verify throughput telemetry per-lane EPS fields exist
                tp = data["throughput_telemetry"]
                assert "priority_outbound_eps" in tp
                assert "standard_outbound_eps" in tp
                assert "outbound_eps" in tp


# ---------------------------------------------------------------------------
# 6. Graylog Kill-Chain & GELF _broker_topic Field Tests
# ---------------------------------------------------------------------------

class TestKillChainAndGelfTopicMetadata:
    """Verifies _broker_topic injection and Kill-Chain per-lane order validation."""

    def test_gelf_transformer_injects_broker_topic(self):
        raw_event = {
            "client_ip": "10.0.0.99",
            "event_type": "PORT_SCAN",
            "timestamp": 1760000000.0,
            "target_resource": "/admin",
            "status_code": 200,
            "severity": 4,
            "raw_payload": {"msg": "scan"},
        }
        raw_msg = json.dumps(raw_event).encode("utf-8")

        # Standard lane
        gelf_standard = transform_to_gelf(
            raw_msg,
            broker_topic="security-logs",
            broker_partition=0,
            broker_offset=10,
        )
        assert "_broker_topic" in gelf_standard
        assert gelf_standard["_broker_topic"] == "security-logs"
        assert gelf_standard["_broker_partition"] == 0
        assert gelf_standard["_broker_offset"] == 10

        # Priority lane
        gelf_priority = transform_to_gelf(
            raw_msg,
            broker_topic="security-logs.priority",
            broker_partition=1,
            broker_offset=25,
        )
        assert "_broker_topic" in gelf_priority
        assert gelf_priority["_broker_topic"] == "security-logs.priority"
        assert gelf_priority["_broker_partition"] == 1
        assert gelf_priority["_broker_offset"] == 25

    def test_kill_chain_per_lane_ordering_and_cross_lane_best_effort(self):
        state = MockGraylogState()

        # Attacker IP 10.0.0.99 sends events across two topics
        # Standard topic: PORT_SCAN (ts=100.0) -> BRUTE_FORCE (ts=105.0)
        # Priority topic: IOT_CONTROL (ts=110.0) - e.g. severe intrusion alert
        records = [
            {
                "timestamp": 100.0,
                "_client_ip": "10.0.0.99",
                "_event_type": "PORT_SCAN",
                "_broker_topic": "security-logs",
                "_broker_partition": 0,
                "_broker_offset": 1,
            },
            {
                "timestamp": 110.0,
                "_client_ip": "10.0.0.99",
                "_event_type": "IOT_CONTROL",
                "_broker_topic": "security-logs.priority",
                "_broker_partition": 0,
                "_broker_offset": 1,
            },
            {
                "timestamp": 105.0,
                "_client_ip": "10.0.0.99",
                "_event_type": "BRUTE_FORCE",
                "_broker_topic": "security-logs",
                "_broker_partition": 0,
                "_broker_offset": 2,
            },
        ]

        state.ingest_gelf_records(records)
        report = state.get_verification_report()

        kc = report["kill_chain_verification"]
        assert kc["attacker_ip"] == "10.0.0.99"
        assert kc["cross_lane_ordering"] == "best effort"
        assert kc["per_lane_ordering_verified"] is True
        assert kc["strict_chronological_order_verified"] is True

        lanes = kc["lanes"]
        assert "security-logs" in lanes
        assert "security-logs.priority" in lanes
        assert lanes["security-logs"]["timestamps_monotonic"] is True
        assert lanes["security-logs.priority"]["timestamps_monotonic"] is True
        assert lanes["security-logs"]["same_partition_verified"] is True
        assert lanes["security-logs.priority"]["same_partition_verified"] is True
