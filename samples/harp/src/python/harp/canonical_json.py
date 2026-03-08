"""RFC 8785 JSON Canonicalization Scheme (JCS).

Uses the ``canonicaljson`` package which produces deterministic, sorted,
compact JSON — compatible with RFC 8785 for the types used in HARP.

Mirrors Harp.Common/CanonicalJson.cs from the C# implementation.
"""

from __future__ import annotations

from typing import Any

import canonicaljson


def _strip_nulls_recursive(obj: Any) -> Any:
    """Recursively strip None-valued keys from dicts.

    Mirrors C#'s ``JsonIgnoreCondition.WhenWritingNull``.
    """
    if isinstance(obj, dict):
        return {k: _strip_nulls_recursive(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls_recursive(item) for item in obj]
    return obj


def jcs_canonicalize(obj: Any) -> str:
    """Canonicalize an object to a JCS string, stripping nulls."""
    cleaned = _strip_nulls_recursive(obj)
    return canonicaljson.encode_canonical_json(cleaned).decode("utf-8")


def jcs_canonicalize_utf8(obj: Any) -> bytes:
    """Canonicalize an object to JCS UTF-8 bytes, stripping nulls."""
    cleaned = _strip_nulls_recursive(obj)
    return canonicaljson.encode_canonical_json(cleaned)
