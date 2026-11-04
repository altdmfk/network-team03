"""Shared Authentication Helper for Simulators and Client Snippets.

Provides HMAC-SHA256 signature generation matching src/middleware/auth.py.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional, Union

try:
    from middleware.auth import generate_hmac_signature_headers as _canonical_generate
except ImportError:
    _canonical_generate = None


def generate_hmac_signature_headers(
    api_key: str,
    raw_body: Union[bytes, str, Dict[str, Any], List[Any]],
    timestamp: Optional[float] = None,
) -> Dict[str, str]:
    """Generates HMAC-SHA256 authentication headers (X-Signature and X-Timestamp)

    satisfying verify_hmac_signature specification in auth.py.
    """
    if _canonical_generate is not None:
        return _canonical_generate(api_key, raw_body, timestamp=timestamp)

    if timestamp is None:
        timestamp = time.time()
    ts_str = f"{timestamp:.6f}"

    if isinstance(raw_body, (dict, list)):
        body_bytes = json.dumps(
            raw_body, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    elif isinstance(raw_body, str):
        body_bytes = raw_body.encode("utf-8")
    elif isinstance(raw_body, (bytes, bytearray)):
        body_bytes = bytes(raw_body)
    else:
        body_bytes = str(raw_body).encode("utf-8")

    sig = hmac.new(
        api_key.encode("utf-8"),
        f"{ts_str}:".encode("utf-8") + body_bytes,
        hashlib.sha256,
    ).hexdigest()

    return {
        "X-Signature": sig,
        "X-Timestamp": ts_str,
    }


generate_hmac_auth_headers = generate_hmac_signature_headers
