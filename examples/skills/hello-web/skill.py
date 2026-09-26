"""A deliberately small skill: fetch a URL, return its text.

It exists to be packaged, published, verified and installed, so the registry
commands in the README have something real to operate on. The tool it exposes is
described by fetch_page.nts.json, which declares that it reaches the network --
the sort of thing you want stated before you install a stranger's skill.
"""

from __future__ import annotations

import re
import urllib.request

_TAGS = re.compile(r"<[^>]+>")


def fetch_page(url: str, max_chars: int = 2000) -> str:
    """Fetch a URL and return its text with markup stripped.

    Args:
        url: The page to fetch. Must be http or https.
        max_chars: Truncate the result to this many characters.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError("only http and https URLs are supported, got %r" % (url,))
    request = urllib.request.Request(url, headers={"user-agent": "attestry-hello-web"})
    with urllib.request.urlopen(request, timeout=30) as handle:
        charset = handle.headers.get_content_charset() or "utf-8"
        body = handle.read(max_chars * 8).decode(charset, "replace")
    return _TAGS.sub(" ", body)[:max_chars].strip()
