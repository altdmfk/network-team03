import asyncio
import threading
from unittest.mock import MagicMock

import pytest

import config
import ingestor
from config import BROKER_PARTITIONS, BROKER_PRIORITY_TOPIC, BROKER_TOPIC
from ingestor import _broker_lag_refresh_loop, app, lifespan
from middleware.lightweight_broker import LightweightProducer


class TestLagCacheRefresh:
    """
    Verification suite for the periodic lag cache refresh and partition count cache:
    1. Zero DB queries on produce() hot path.
    2. Cold-start returns 0 (safe default).
    3. Background task periodically refreshes cache via asyncio.to_thread.
    4. Exception resilience: transient DB failures do not kill the loop.
    5. Startup/shutdown registration and cancellation.
    """

    def test_cold_start_returns_safe_zero(self, tmp_path):
        """Cold-start returns 0 before any cache refresh runs."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=100,
        )
        try:
            assert producer.get_cached_lag() == 0
            assert producer.get_cached_lag(BROKER_TOPIC) == 0
            assert producer.get_cached_lag(BROKER_PRIORITY_TOPIC) == 0

            producer.produce(BROKER_TOPIC, value=b'{"event": "cold_start"}')
            producer.flush()
        finally:
            producer.close()

    def test_produce_hot_path_never_calls_database(self, tmp_path):
        """produce() hot path has ZERO synchronous SQLite SELECT queries."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=100,
        )
        try:
            producer.update_cached_lag(10, topic=BROKER_TOPIC)
            assert producer.get_cached_lag(BROKER_TOPIC) == 10

            # Warm up partition count cache (1st produce per topic)
            producer.produce(BROKER_TOPIC, value=b'{"warmup": true}')

            mock_get_lag = MagicMock(
                side_effect=RuntimeError("Storage SELECT must NEVER be called in produce()!")
            )
            mock_get_parts = MagicMock(
                side_effect=RuntimeError(
                    "get_topic_partitions SELECT must NEVER be called in produce() hot path!"
                )
            )
            producer._storage.get_total_unconsumed_lag = mock_get_lag
            producer._storage.get_topic_partitions = mock_get_parts

            for i in range(50):
                producer.produce(BROKER_TOPIC, value=f'{{"i": {i}}}')

            assert mock_get_lag.call_count == 0
            assert mock_get_parts.call_count == 0
        finally:
            producer._storage.get_total_unconsumed_lag = lambda **k: 0
            producer.close()

    @pytest.mark.asyncio
    async def test_background_refresh_loop_updates_producer_cache(self, tmp_path):
        """Background task refreshes cache via asyncio.to_thread."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=50,
        )
        mock_mw = MagicMock()
        mock_mw.producer = producer

        try:
            assert producer.get_cached_lag(BROKER_TOPIC) == 0

            def _fake_lag(group_id=None, topic=None):
                if topic == BROKER_TOPIC:
                    return 42
                return 0

            producer._storage.get_total_unconsumed_lag = MagicMock(side_effect=_fake_lag)

            refresh_task = asyncio.create_task(
                _broker_lag_refresh_loop(mw=mock_mw, interval=0.05)
            )
            await asyncio.sleep(0.12)

            assert producer.get_cached_lag(BROKER_TOPIC) == 42

            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        finally:
            producer.close()

    @pytest.mark.asyncio
    async def test_background_refresh_loop_exception_resilience(self, tmp_path):
        """Exception resilience: loop catches DB errors and retries without dying."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=50,
        )
        mock_mw = MagicMock()
        mock_mw.producer = producer

        try:
            call_count = 0

            def _flaky_lag(group_id=None, topic=None):
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    raise RuntimeError(
                        "transient SQLite database locked (BEGIN IMMEDIATE contention)"
                    )
                return 77

            producer._storage.get_total_unconsumed_lag = MagicMock(side_effect=_flaky_lag)

            refresh_task = asyncio.create_task(
                _broker_lag_refresh_loop(mw=mock_mw, interval=0.05)
            )
            await asyncio.sleep(0.25)

            assert not refresh_task.done()
            assert producer.get_cached_lag(BROKER_TOPIC) == 77
            assert call_count > 2

            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        finally:
            producer.close()

    @pytest.mark.asyncio
    async def test_startup_shutdown_lifecycle(self):
        """Task registered in startup/lifespan and cancelled in shutdown."""
        async with lifespan(app):
            task = ingestor._lag_refresh_task
            assert task is not None
            assert not task.done()

        assert ingestor._lag_refresh_task is None

    def test_configurable_interval_setting(self):
        """Interval is configurable via LAG_REFRESH_INTERVAL_SEC."""
        assert hasattr(config, "LAG_REFRESH_INTERVAL_SEC")
        assert config.LAG_REFRESH_INTERVAL_SEC == 1.0

        custom_settings = config.load_settings({"LAG_REFRESH_INTERVAL_SEC": "2.5"})
        assert custom_settings.lag_refresh_interval_sec == 2.5

    def test_partition_count_cached_after_first_produce(self, tmp_path):
        """Verifies _get_num_partitions queries DB only on the 1st call per topic and never on subsequent calls."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(db_path=db_path, num_partitions=BROKER_PARTITIONS)
        try:
            orig_get_parts = producer._storage.get_topic_partitions
            spy_get_parts = MagicMock(side_effect=orig_get_parts)
            producer._storage.get_topic_partitions = spy_get_parts

            producer.produce(BROKER_TOPIC, key="10.0.0.1", value=b'{"seq": 0}')
            assert spy_get_parts.call_count == 1
            assert producer._partition_count_cache.get(BROKER_TOPIC) == BROKER_PARTITIONS

            # Replace storage method with an error to prove 2nd+ calls never touch SQLite
            producer._storage.get_topic_partitions = MagicMock(
                side_effect=RuntimeError("get_topic_partitions must not be called on cache hit!")
            )

            for i in range(1, 100):
                producer.produce(BROKER_TOPIC, key=f"10.0.0.{i}", value=f'{{"seq": {i}}}')

            assert producer._storage.get_topic_partitions.call_count == 0
            producer.flush()
        finally:
            producer.close()

    def test_partition_count_cache_new_topic_at_runtime(self, tmp_path):
        """Verifies a new topic introduced at runtime is queried/auto-created once and then cached."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(db_path=db_path, num_partitions=BROKER_PARTITIONS)
        try:
            orig_get_parts = producer._storage.get_topic_partitions
            spy_get_parts = MagicMock(side_effect=orig_get_parts)
            producer._storage.get_topic_partitions = spy_get_parts

            new_topic = f"{BROKER_TOPIC}.custom-runtime"
            assert new_topic not in producer._partition_count_cache

            for i in range(20):
                producer.produce(new_topic, key=f"192.168.1.{i}", value=f'{{"seq": {i}}}')

            assert spy_get_parts.call_count == 1
            assert producer._partition_count_cache[new_topic] == BROKER_PARTITIONS
            producer.flush()
        finally:
            producer.close()

    def test_partition_count_cache_multithread_safety(self, tmp_path):
        """Verifies thread-safe access to _partition_count_cache under concurrent access."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(db_path=db_path, num_partitions=BROKER_PARTITIONS)
        try:
            orig_get_parts = producer._storage.get_topic_partitions
            spy_get_parts = MagicMock(side_effect=orig_get_parts)
            producer._storage.get_topic_partitions = spy_get_parts

            barrier = threading.Barrier(8)
            results = []
            errors = []

            def worker():
                try:
                    barrier.wait()
                    for _ in range(50):
                        n = producer._get_num_partitions(BROKER_TOPIC)
                        results.append(n)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors
            assert len(results) == 400
            assert all(r == BROKER_PARTITIONS for r in results)
            # Protected by _partition_count_lock, DB query happens only once
            assert spy_get_parts.call_count == 1
        finally:
            producer.close()
