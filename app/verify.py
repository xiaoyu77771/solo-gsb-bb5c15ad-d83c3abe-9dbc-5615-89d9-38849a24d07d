"""Read-only verification of a stored audit against its original text.

The stored ``raw_text`` is fed back through the current bidi parser and the
fresh result is compared **field by field** with the persisted ``result``.
This detects records produced by older parser versions or tampered storage.

Difference locations are reported as [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901)
strings (e.g. ``/controls/0/risk``); array items are located by their index.
Every difference carries ``stored_present`` / ``recomputed_present`` flags so
that a missing field can be distinguished from a field whose value is
``null``. Nothing here mutates the record.
"""

from __future__ import annotations

from typing import Any

from .bidi import parse_bidi

# Sentinel for "key / index absent on this side" -- distinct from None, which
# is a legitimate JSON value and must not be conflated with absence.
_MISSING = object()


def _escape_token(token: Any) -> str:
    """Escape one JSON Pointer reference token (``~`` -> ``~0``, ``/`` -> ``~1``)."""
    return str(token).replace("~", "~0").replace("/", "~1")


def _token_sort_key(token: str) -> tuple[int, Any]:
    # Array index tokens sort numerically (2 < 10), object-key tokens sort
    # lexically; the two never share a parent, the tag just gives a total
    # order for the key function.
    if token == "0" or (token.isdigit() and not token.startswith("0")):
        return (0, int(token))
    return (1, token)


def _pointer_sort_key(path: str) -> list[tuple[int, Any]]:
    if path == "":
        return []
    keys: list[tuple[int, Any]] = []
    for raw in path[1:].split("/"):
        # RFC 6901 decoding: ~1 first, then ~0.
        token = raw.replace("~1", "/").replace("~0", "~")
        keys.append(_token_sort_key(token))
    return keys


def _json_equal(left: Any, right: Any) -> bool:
    """Strict JSON equality: booleans are not numbers, numeric values compare by value."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return left == right


def _diff(
    stored: Any,
    recomputed: Any,
    path: str,
    out: list[dict[str, Any]],
) -> None:
    stored_present = stored is not _MISSING
    recomputed_present = recomputed is not _MISSING

    if stored_present and recomputed_present:
        if isinstance(stored, dict) and isinstance(recomputed, dict):
            for key in set(stored) | set(recomputed):
                _diff(
                    stored.get(key, _MISSING),
                    recomputed.get(key, _MISSING),
                    f"{path}/{_escape_token(key)}",
                    out,
                )
            return
        if isinstance(stored, list) and isinstance(recomputed, list):
            for index in range(max(len(stored), len(recomputed))):
                left = stored[index] if index < len(stored) else _MISSING
                right = recomputed[index] if index < len(recomputed) else _MISSING
                _diff(left, right, f"{path}/{index}", out)
            return
        if _json_equal(stored, recomputed):
            return

    # One side is missing, both leaves differ, or their JSON types diverged.
    out.append({
        "path": path,
        "stored_value": None if stored is _MISSING else stored,
        "recomputed_value": None if recomputed is _MISSING else recomputed,
        "stored_present": stored is not _MISSING,
        "recomputed_present": recomputed is not _MISSING,
    })


def diff_results(
    stored: dict[str, Any], recomputed: dict[str, Any]
) -> list[dict[str, Any]]:
    """Fieldwise diff of two parse results, sorted by JSON Pointer.

    When an object key or array index exists on only one side, the whole
    remaining subtree is reported as one difference at that pointer instead
    of one entry per descendant leaf.
    """
    differences: list[dict[str, Any]] = []
    _diff(stored, recomputed, "", differences)
    differences.sort(key=lambda entry: _pointer_sort_key(entry["path"]))
    return differences


def verify_stored_audit(record: dict[str, Any]) -> dict[str, Any]:
    """Re-parse a stored record's raw text and compare it with its saved result."""
    recomputed = parse_bidi(record["raw_text"]).to_dict()
    differences = diff_results(record["result"], recomputed)
    return {
        "id": record["id"],
        "consistent": not differences,
        "diff_count": len(differences),
        "differences": differences,
    }
