"""The one JSON grammar of ARK: I-JSON, RFC 7493 (stdlib only).

Imported by every tool that turns JSON bytes into a decision: ``freeze_manifest``
(integrity gate), ``release_bundle`` (build and closed-world verifier), ``release_gate``
(manifest ``artifact`` at tag time), ``release_sbom`` (pin check) and ``validate_run``
(kernels, policy, schemas). Like ``ark_semver`` it lives in its own stdlib-only module
because the release gate runs before any third-party package is installed.

Python's ``json`` is more permissive than the documents ARK decides on. Each accepted
extra is a parser differential: another reader of the same bytes sees a different
document, so an audit verdict would depend on who parsed the input.

* Duplicate object member names (RFC 7493 section 2.3). Python keeps the last value,
  other parsers the first or reject. Names are compared after escape processing, as the
  RFC requires: ``"a"`` and ``"\\u0061"`` are the same name.
* ``NaN``, ``Infinity``, ``-Infinity``: not JSON at all (RFC 8259 section 6); Python
  accepts them by default.
* Surrogate and noncharacter code points in member names or string values, escaped or
  not (RFC 7493 section 2.1). Python decodes a lone ``\\ud800`` into a string that cannot
  be encoded as UTF-8 again.

Out of scope here (RFC 7493 SHOULD, not MUST): numbers beyond IEEE 754 double precision.
Callers that need a bound check it themselves (``validate_run`` maps the int-digit limit
to ``NEG.KERNEL.UNREADABLE``).

Every refusal is a ``ValueError`` (``StrictJSONError``), so callers that already treat
``json.JSONDecodeError`` as unreadable input need no new branch.
"""
from __future__ import annotations

import json
from typing import Any, List, Tuple


class StrictJSONError(ValueError):
    """The text is JSON for Python but not I-JSON."""


def _forbidden_code_point(text: str) -> str | None:
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            return f"surrogate U+{cp:04X}"
        if 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE:
            return f"noncharacter U+{cp:04X}"
    return None


def _check_string(text: str, where: str) -> None:
    reason = _forbidden_code_point(text)
    if reason:
        raise StrictJSONError(f"{reason} in {where}")


def _object(pairs: List[Tuple[str, Any]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        _check_string(key, "an object member name")
        if key in obj:
            raise StrictJSONError(f"duplicate object member name {key!a}")
        if isinstance(value, str):
            _check_string(value, f"the value of {key!a}")
        obj[key] = value
    return obj


def _constant(name: str) -> Any:
    raise StrictJSONError(f"non-finite number {name} is not JSON")


def _check_array_strings(value: Any) -> None:
    """Strings directly inside arrays (object values are checked in ``_object``)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            for element in item:
                if isinstance(element, str):
                    _check_string(element, "an array element")
                elif isinstance(element, (list, dict)):
                    stack.append(element)
        elif isinstance(item, dict):
            stack.extend(v for v in item.values() if isinstance(v, (list, dict)))


def loads(text: str) -> Any:
    """Parse ``text`` as I-JSON. Raises ``ValueError`` (incl. ``StrictJSONError``)."""
    value = json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
    if isinstance(value, str):
        _check_string(value, "the top-level string")
    _check_array_strings(value)
    return value


def load_path(path: str) -> Any:
    """Read a UTF-8 file and parse it with :func:`loads`."""
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
