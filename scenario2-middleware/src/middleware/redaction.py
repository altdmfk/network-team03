import json
import re
from typing import Any, List, Optional, Set

DEFAULT_REDACTION_PATTERNS: List[str] = [
    "password",
    "passwd",
    "token",
    "api_key",
    "secret",
    "authorization",
    "cookie",
    "session",
]


def _normalize_key(key: Any) -> str:
    """
    Normalizes keys by converting camelCase and kebab-case to snake_case,
    lowercasing, and stripping whitespace.
    e.g. 'apiKey' -> 'api_key', 'Session-Token' -> 'session_token'
    """
    s = str(key).strip()
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_")


def is_sensitive_key(key: Any, patterns: Optional[List[str]] = None) -> bool:
    """
    Checks if a key matches any configured redaction pattern case-insensitively.
    Matches exact tokens, snake_case substrings, and common key variants.
    """
    target = _normalize_key(key)
    active_patterns = patterns if patterns is not None else DEFAULT_REDACTION_PATTERNS

    for pat in active_patterns:
        norm_pat = _normalize_key(pat)
        if not norm_pat:
            continue
        # Direct equality or substring containment (e.g. 'api_key' in 'api_key_id', 'token' in 'session_token')
        if norm_pat in target:
            return True
    return False


def redact_sensitive_data(
    data: Any,
    patterns: Optional[List[str]] = None,
    replacement: str = "[REDACTED]",
    _visited: Optional[Set[int]] = None,
) -> Any:
    """
    Recursively redacts values of keys matching sensitive patterns across nested
    dictionaries, lists, and embedded JSON strings.
    Protects against circular references via object id tracking.
    """
    if data is None:
        return None

    if _visited is None:
        _visited = set()

    data_id = id(data)
    if isinstance(data, (dict, list)):
        if data_id in _visited:
            return replacement
        _visited.add(data_id)

    try:
        if isinstance(data, dict):
            redacted: dict[str, Any] = {}
            for k, v in data.items():
                if is_sensitive_key(k, patterns):
                    redacted[str(k)] = replacement
                else:
                    redacted[str(k)] = redact_sensitive_data(
                        v, patterns=patterns, replacement=replacement, _visited=_visited
                    )
            return redacted

        if isinstance(data, list):
            return [
                redact_sensitive_data(
                    item, patterns=patterns, replacement=replacement, _visited=_visited
                )
                for item in data
            ]

        if isinstance(data, (bytes, bytearray)):
            try:
                decoded_str = data.decode("utf-8")
                parsed = json.loads(decoded_str)
                if isinstance(parsed, (dict, list)):
                    redacted_obj = redact_sensitive_data(
                        parsed, patterns=patterns, replacement=replacement, _visited=_visited
                    )
                    return json.dumps(
                        redacted_obj, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")
            except Exception:
                pass
            return data

        if isinstance(data, str):
            stripped = data.strip()
            # Attempt to parse embedded JSON string
            if (stripped.startswith("{") and stripped.endswith("}")) or (
                stripped.startswith("[") and stripped.endswith("]")
            ):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, (dict, list)):
                        redacted_obj = redact_sensitive_data(
                            parsed,
                            patterns=patterns,
                            replacement=replacement,
                            _visited=_visited,
                        )
                        return json.dumps(
                            redacted_obj, separators=(",", ":"), ensure_ascii=False
                        )
                except Exception:
                    pass
            return data

        return data
    finally:
        if isinstance(data, (dict, list)) and data_id in _visited:
            _visited.remove(data_id)
