#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re

_URL_RE = re.compile(
    r"(?i)(?:(?:https?|ftps?|hxxps?|fxps?)://|www\d{0,3}\.)[^\s<>\"'`)\]}]+"
)

_URL_SCHEME_SPACED_RE = re.compile(
    r"(?i)(?:https?|ftps?|hxxps?|fxps?)\s*:\s*/\s*/"
    r"(?:\s*[\w-]+(?:\s*\.\s*[\w-]+)*(?:\s*/\s*[^\s]*)*)?"
)

_URL_SPACED_RE = re.compile(
    r"(?i)www\d{0,3}(?:\s*\.\s*[\w-]+)+(?:\s*/\s*[^\s]+)*"
)

_WEB_SCHEME_RE = re.compile(r"(?i)^(?:https?|ftps?|hxxps?|fxps?)://|^www\d{0,3}\.")

_WS_RE = re.compile(r"\s+")

_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?</\1>")
_TAG_RE = re.compile(r"(?s)<[^>]+>")

_ATTR_LINK_RE = re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
