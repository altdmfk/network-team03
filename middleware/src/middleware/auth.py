import hashlib
import hmac
import logging
import os
import threading
import time
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Tuple

from fastapi import HTTPException, Request, status

logger = logging.getLogger("soar.auth")

REPLAY_WINDOW_SECONDS: float = 300.0


def _load_keys_from_value_or_file(raw_value: Optional[str]) -> List[str]:
    """
    Parses keys from an environment variable or secret file path.
    If the string points to an existing file, reads lines/commas from the file.
    Otherwise, splits the string on commas and strips whitespace.
    """
    if not raw_value:
        return []

    stripped = raw_value.strip()
    if not stripped:
        return []

    # Check if raw_value points to an existing file (e.g. Docker / Kubernetes secret)
    try:
        p = Path(stripped)
        if p.is_file():
            content = p.read_text(encoding="utf-8").strip()
            # File may contain comma-separated keys or newline-separated keys
            keys: List[str] = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for chunk in line.split(","):
                    c = chunk.strip()
                    if c:
                        keys.append(c)
            return keys
    except (OSError, ValueError):
        pass

    # Treat as comma-separated string
    return [k.strip() for k in stripped.split(",") if k.strip()]


def get_ingest_api_keys() -> List[str]:
    """Retrieves allowed ingest API keys from INGEST_API_KEYS or INGEST_API_KEYS_FILE."""
    file_path = os.environ.get("INGEST_API_KEYS_FILE")
    if file_path:
        keys = _load_keys_from_value_or_file(file_path)
        if keys:
            return keys
    return _load_keys_from_value_or_file(os.environ.get("INGEST_API_KEYS", ""))


def get_admin_api_keys() -> List[str]:
    """Retrieves allowed admin API keys from ADMIN_API_KEY or ADMIN_API_KEY_FILE."""
    file_path = os.environ.get("ADMIN_API_KEY_FILE")
    if file_path:
        keys = _load_keys_from_value_or_file(file_path)
        if keys:
            return keys
    return _load_keys_from_value_or_file(os.environ.get("ADMIN_API_KEY", ""))


def is_auth_enabled() -> bool:
    """Checks whether API authentication is enabled (default is True unless AUTH_ENABLED=false)."""
    val = os.environ.get("AUTH_ENABLED", "true").strip().lower()
    return val not in ("0", "false", "no", "off")


class ReplayProtectionCache:
    """
    Thread-safe replay protection cache.
    Stores (signature, timestamp) tuples within the 300-second window.
    Entries older than the window are periodically pruned.
    """

    def __init__(self, window_seconds: float = REPLAY_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._seen: Set[str] = set()
        self._timestamps: List[Tuple[float, str]] = []
        self._lock = threading.Lock()

    def add_if_not_present(self, signature: str, timestamp: float) -> bool:
        """
        Returns True if the signature is newly recorded.
        Returns False if a replay is detected.
        """
        now = time.time()
        with self._lock:
            # Prune old entries
            cutoff = now - self.window_seconds
            while self._timestamps and self._timestamps[0][0] < cutoff:
                _, old_sig = self._timestamps.pop(0)
                self._seen.discard(old_sig)

            if signature in self._seen:
                return False

            self._seen.add(signature)
            self._timestamps.append((timestamp, signature))
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
            self._timestamps.clear()


replay_cache = ReplayProtectionCache()


class AuthRole(str, Enum):
    INGEST = "ingest"
    ADMIN = "admin"


def verify_api_key_match(provided_key: str, allowed_keys: List[str]) -> bool:
    """Performs constant-time comparison across allowed keys."""
    for allowed in allowed_keys:
        if hmac.compare_digest(provided_key, allowed):
            return True
    return False


def verify_hmac_signature(
    raw_body: bytes,
    timestamp_str: str,
    provided_signature: str,
    allowed_keys: List[str],
) -> Optional[str]:
    """
    Verifies HMAC-SHA256 signature over raw_body (and timestamp variants) using constant-time comparison.
    Returns the matching key on success, or None on failure.
    """
    prov_sig = provided_signature.strip().lower()

    for key in allowed_keys:
        key_bytes = key.encode("utf-8")

        # Standard: HMAC-SHA256 over raw_body
        expected_sig1 = hmac.new(key_bytes, raw_body, hashlib.sha256).hexdigest().lower()
        if hmac.compare_digest(prov_sig, expected_sig1):
            return key

        # Variant: HMAC-SHA256 over timestamp + raw_body
        ts_bytes = timestamp_str.encode("utf-8")
        expected_sig2 = hmac.new(key_bytes, ts_bytes + raw_body, hashlib.sha256).hexdigest().lower()
        if hmac.compare_digest(prov_sig, expected_sig2):
            return key

        # Variant: HMAC-SHA256 over f"{timestamp}:{raw_body}"
        expected_sig3 = hmac.new(
            key_bytes,
            f"{timestamp_str}:".encode("utf-8") + raw_body,
            hashlib.sha256,
        ).hexdigest().lower()
        if hmac.compare_digest(prov_sig, expected_sig3):
            return key

    return None


async def authenticate_request(request: Request, role: AuthRole) -> str:
    """
    FastAPI dependency logic that validates authentication.
    Returns the authenticated client identity (e.g. key hash/value or 'anonymous').
    """
    if not is_auth_enabled():
        return request.headers.get("X-API-Key") or "anonymous"

    if role == AuthRole.INGEST:
        allowed_keys = get_ingest_api_keys()
        auth_role_name = "ingest"
    else:
        allowed_keys = get_admin_api_keys()
        auth_role_name = "admin"

    if not allowed_keys:
        logger.error("Authentication is enabled but no %s keys are configured.", auth_role_name)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication required: no {auth_role_name} keys configured on server.",
            headers={"WWW-Authenticate": "ApiKey, Signature"},
        )

    api_key_header = request.headers.get("X-API-Key")
    sig_header = request.headers.get("X-Signature")
    ts_header = request.headers.get("X-Timestamp")

    # 1. Scheme A: X-API-Key verification
    if api_key_header is not None:
        if verify_api_key_match(api_key_header, allowed_keys):
            return api_key_header
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid {auth_role_name} API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. Scheme B: HMAC-SHA256 Signature verification
    if sig_header is not None:
        if not ts_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Timestamp header for HMAC signature verification.",
                headers={"WWW-Authenticate": "Signature"},
            )

        # Parse timestamp
        try:
            req_ts = float(ts_header.strip())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid X-Timestamp header format. Expected Unix epoch timestamp.",
                headers={"WWW-Authenticate": "Signature"},
            )

        # Verify 300-second replay window
        now = time.time()
        if abs(now - req_ts) > REPLAY_WINDOW_SECONDS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Request timestamp outside allowed {int(REPLAY_WINDOW_SECONDS)}s replay window.",
                headers={"WWW-Authenticate": "Signature"},
            )

        # Replay protection check
        sig_id = f"{sig_header.strip()}:{ts_header.strip()}"
        if not replay_cache.add_if_not_present(sig_id, req_ts):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Replay attack detected: signature has already been used.",
                headers={"WWW-Authenticate": "Signature"},
            )

        raw_body = await request.body()
        matched_key = verify_hmac_signature(raw_body, ts_header, sig_header, allowed_keys)
        if matched_key is not None:
            return matched_key

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid HMAC-SHA256 signature for {auth_role_name} endpoint.",
            headers={"WWW-Authenticate": "Signature"},
        )

    # Neither credential provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Authentication required for {auth_role_name} endpoint. Provide X-API-Key or X-Timestamp + X-Signature.",
        headers={"WWW-Authenticate": "ApiKey, Signature"},
    )


async def require_ingest_auth(request: Request) -> str:
    """FastAPI dependency for ingest routes (/ingest, /ingest/batch)."""
    return await authenticate_request(request, AuthRole.INGEST)


async def require_admin_auth(request: Request) -> str:
    """FastAPI dependency for admin routes (/metrics/reset, /admin/*)."""
    return await authenticate_request(request, AuthRole.ADMIN)
