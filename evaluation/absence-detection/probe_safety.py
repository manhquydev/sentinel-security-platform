"""Shared safety guard for the runtime probers in this directory.

Both probers send authenticated requests at a live target, so the loopback assertion is the boundary
that keeps a mistyped origin from pointing a security prober at something that is not ours. It existed
in only one of the two — a review caught the exposure-gap prober running without it. A guard that is
copy-pasted is a guard that drifts, so it lives here and both import it.
"""

from __future__ import annotations

import sys
from urllib.parse import urlparse

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def assert_local(*urls: str) -> None:
    """Exit non-zero unless every origin resolves to loopback. Fails closed on an unparseable URL."""
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if host not in LOOPBACK:
            print(f"FAIL: refusing non-loopback origin {u!r} — these probers may only target the "
                  "local disposable lab target.")
            sys.exit(2)
