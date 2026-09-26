"""Timestamps.

Everything Attestry writes is UTC and RFC 3339 with a trailing ``Z``. Local
time never enters the ledger: a receipt that says "14:03" is useless six months
later if nobody recorded which 14:03 it was.
"""

from __future__ import annotations

import datetime as _dt
import re

_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"[Tt ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?"
    r"(Z|z|[+-]\d{2}:\d{2})$"
)

_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def now_rfc3339() -> str:
    """Current UTC instant, second precision, e.g. ``2026-09-25T14:03:07Z``."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(value: str) -> _dt.datetime:
    """Parse an RFC 3339 timestamp into an aware :class:`datetime`."""
    match = _RFC3339.match(value.strip())
    if not match:
        raise ValueError("not an RFC 3339 timestamp: %r" % (value,))
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    frac = match.group(7)
    micro = int((frac or "").ljust(6, "0")[:6]) if frac else 0
    offset = match.group(8)
    if offset in ("Z", "z"):
        tz = _dt.timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        delta = _dt.timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
        tz = _dt.timezone(sign * delta)
    return _dt.datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)


def pretty_when(value: str) -> str:
    """Render a timestamp the way a person reads it: ``25 Sep 2026 at 14:03 UTC``.

    Used by the receipt renderer. Unparseable input is returned unchanged rather
    than raising, because a receipt with an odd date is still worth showing.
    """
    try:
        moment = parse_rfc3339(value).astimezone(_dt.timezone.utc)
    except ValueError:
        return value
    return "%d %s %d at %02d:%02d UTC" % (
        moment.day,
        _MONTHS[moment.month - 1],
        moment.year,
        moment.hour,
        moment.minute,
    )
