#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_part import _decode_part
from is_attachment import _is_attachment


def _extract_bodies(msg: EmailMessage) -> tuple[list[str], list[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if _is_attachment(part):
            continue
        ctype = (part.get_content_type() or "").lower()
        if ctype == "text/plain":
            plain_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))
    return plain_parts, html_parts
