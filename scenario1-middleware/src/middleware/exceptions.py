class MiddlewareError(Exception):
    """Base exception for all SOAR broker buffering middleware errors."""


class ConfigurationError(MiddlewareError):
    """Raised when environment or runtime configuration fails validation."""


class ProducerBackpressureError(MiddlewareError):
    """Raised when the local broker producer queue remains full after retries."""


class ProducerEnqueueError(MiddlewareError):
    """Raised when the broker producer fails to enqueue a message due to a broker/client error."""


class DownstreamDeliveryError(MiddlewareError):
    """Raised when downstream SIEM (Graylog) rejects or fails to receive a GELF batch."""


class OffsetCommitError(MiddlewareError):
    """Raised when synchronous per-partition broker offset commit fails."""


class DeadLetterStoreError(MiddlewareError):
    """Raised when reading or writing the Dead-Letter Queue store fails."""
