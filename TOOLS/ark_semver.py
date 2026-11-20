"""The one SemVer 2.0.0 grammar of ARK (stdlib only).

Imported by ``validate_run`` (kernel ``version`` check, ``NEG.KERNEL.INVALID_SEMVER``)
and by ``release_gate`` (the ``VERSION`` file at release time), so both apply the
same rule. It lives in its own module because the release gate runs before any
third-party package is installed and must not import ``validate_run`` (which needs
``jsonschema``): cross-family/Equalita finding ARK-EQ-02, 2026-10-21.

Official semver.org regex ("Backus-Naur Form Grammar" appendix), with two
tightenings over a verbatim copy:

* ``[0-9]`` instead of ``\\d`` and ``re.ASCII``: ``\\d`` matches every Unicode
  decimal digit, so ``1.0.1`` followed by a fullwidth ``5`` (U+FF15) or an
  Arabic-Indic ``5`` (U+0665) passed (ARK-EQ-01). SemVer identifiers are ASCII.
* ``\\Z`` instead of ``$``: ``$`` also matches before a trailing newline, so
  ``SEMVER_RE.match("1.2.3\\n")`` succeeded.

It forbids leading zeros in numeric identifiers and empty identifiers.
"""
from __future__ import annotations

import re

SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?\Z",
    re.ASCII,
)


def is_semver(text: object) -> bool:
    """True only for a ``str`` that is entirely one SemVer 2.0.0 version."""
    return isinstance(text, str) and SEMVER_RE.fullmatch(text) is not None
