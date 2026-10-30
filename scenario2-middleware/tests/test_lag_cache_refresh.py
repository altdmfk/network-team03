import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

import config
from middleware.lightweight_broker import LightweightProducer, SQLiteBrokerStorage
import ingestor
from ingestor import (
    _broker_lag_refresh_loop,
    app,
    lifespan,
    start_lag_refresh_task,
    stop_lag_refresh_task,
)


class TestLagCacheRefresh:
    """
    Verification suite for the periodic lag cache refresh architecture:
    1. Zero DB queries on produce() hot path.
    2. Cold-start returns 0 (safe default).
    3. Background task periodically refreshes cache via asyncio.to_thread.
    4. Exception resilience: transient DB failures do not kill the loop.
    5. Startup/shutdown registration and cancellation.
    """

    def test_cold_start_returns_safe_zero(self, tmp_path):
        """Requirement 4: Cold-start returns 0 before any cache refresh runs."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=100,
        )
        try:
            # Cold-start should return 0 without executing any queries
            assert producer.get_cached_lag() == 0
            assert producer.get_cached_lag("security-logs") == 0
            assert producer.get_cached_lag("security-logs.priority") == 0

            # Produce should succeed without buffer error
            producer.produce("security-logs", value=b'{"event": "cold_start"}')
            producer.flush()
        finally:
            producer.close()

    def test_produce_hot_path_never_calls_database(self, tmp_path):
        """Requirement 1: produce() hot path has ZERO synchronous SQLite SELECT queries."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=100,
        )
        try:
            # Set a cached lag value
            producer.update_cached_lag(10, topic="security-logs")
            assert producer.get_cached_lag("security-logs") == 10

            # Spy on storage's get_total_unconsumed_lag
            mock_get_lag = MagicMock(side_effect=RuntimeError("Storage SELECT must NEVER be called in produce()!"))
            producer._storage.get_total_unconsumed_lag = mock_get_lag

            # Produce 50 messages on the hot path
            for i in range(50):
                producer.produce("security-logs", value=f'{{"i": {i}}}')

            # Ensure get_total_unconsumed_lag was never invoked during produce()
            assert mock_get_lag.call_count == 0
        finally:
            # Restore to allow clean close
            producer._storage.get_total_unconsumed_lag = lambda **k: 0
            producer.close()

    @pytest.mark.asyncio
    async def test_background_refresh_loop_updates_producer_cache(self, tmp_path):
        """Requirement 3: Background task refreshes cache via asyncio.to_thread."""
        db_path = str(tmp_path / "broker_wal.db")
        producer = LightweightProducer(
            db_path=db_path,
            max_unconsumed_lag=50,
        )
        mock_mw = MagicMock()
        mock_mw.producer = producer

        try:
            # Cold start
            assert producer.get_cached_lag("security-logs") == 0

            # Mock storage returning 42 for security-logs
            def _fake_lag(group_id=None, topic=None):
                if topic == "security-logs":
                    return 42
                return 0

            producer._storage.get_total_unconsumed_lag = MagicMock(side_effect=_fake_lag)

            # Start background loop with very short interval (0.05s)
            refresh_task = asyncio.create_task(
                _broker_lag_refresh_loop(mw=mock_mw, interval=0.05)
            )

            # Wait for task to run at least once
            await asyncio.sleep(0.12)

            # Verify cached lag updated
            assert producer.get_cached_lag("security-logs") == 42

            # Cancel task
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        finally:
            producer.close()

    @pytest.mark.asyncio
    async def test_background_refresh_loop_exception_resilience(self, tmp_path):
        """Requirement 2: Exception resilience - loop catches DB errors and retries without dying."""
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
                    raise Exception("transient SQLite database locked (BEGIN IMMEDIATE contention)")
                return 77

            producer._storage.get_total_unconsumed_lag = MagicMock(side_effect=_flaky_lag)

            refresh_task = asyncio.create_task(
                _broker_lag_refresh_loop(mw=mock_mw, interval=0.05)
            )

            # Allow multiple retries
            await asyncio.sleep(0.25)

            # Loop should still be running (not cancelled, not crashed)
            assert not refresh_task.done()
            assert producer.get_cached_lag("security-logs") == 77
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
        """Requirement 3: Task registered in startup/lifespan and cancelled in shutdown."""
        async with lifespan(app):
            # During lifespan, task should be active and running
            task = ingestor._lag_refresh_task
            assert task is not None
            assert not task.done()

        # After lifespan exits, task should be cancelled/cleaned up
        assert ingestor._lag_refresh_task is None

    def test_configurable_interval_setting(self):
        """Requirement 5: Interval is configurable via LAG_REFRESH_INTERVAL_SEC."""
        assert hasattr(config, "LAG_REFRESH_INTERVAL_SEC")
        assert config.LAG_REFRESH_INTERVAL_SEC == 1.0

        custom_settings = config.load_settings({"LAG_REFRESH_INTERVAL_SEC": "2.5"})
        assert custom_settings.lag_refresh_interval_sec == 2.5
