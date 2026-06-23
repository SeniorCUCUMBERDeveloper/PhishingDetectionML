#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re

I, M = re.IGNORECASE, re.MULTILINE

_HDR = (r"(?:from|to|cc|bcc|sent|date|subject|reply-to|return-path|sender|"
        r"message-id|in-reply-to|references|importance|priority|mime-version|"
        r"content-type|content-transfer-encoding|received|delivered-to|"
        r"authentication-results|dkim-signature|received-spf|organization|x-[\w-]+)")
_QH = r"(?:[ \t>|]*" + _HDR + r"[ \t]*:.*$)"
_DELIVERY_BLOCKS = (

    re.compile(r"^[ \t>|]*-+\s*original message\s*-+.*$(?:\n" + _QH + r")*", I | M),

    re.compile(r"^.*\bforwarded by\b.*$(?:\n" + _QH + r")*", I | M),
    re.compile(r"^[ \t>|]*-+\s*forwarded message\s*-+.*$(?:\n" + _QH + r")*", I | M),

    re.compile(r"^[ \t>|]*on\b.{0,200}\bwrote:[ \t]*$", I | M),

    re.compile(r"^_{5,}[ \t]*$", M),
)

_QUOTED_HEADER_RE = re.compile(r"^[ \t>|]*" + _HDR + r"[ \t]*:.*$", I | M)


def normalize_delivery_artifacts(text: str) -> str:
    for rx in _DELIVERY_BLOCKS:
        text = rx.sub(" ", text)
    text = _QUOTED_HEADER_RE.sub(" ", text)
    return text
