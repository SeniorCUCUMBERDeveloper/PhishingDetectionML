#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from email.message import EmailMessage


def _decode_part(part: EmailMessage) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        try:
            content = part.get_content()
            return content if isinstance(content, str) else str(content)
        except Exception:
            return ""
    charset = part.get_content_charset() or "utf-8"
    for enc in (charset, "utf-8", "latin-1"):
        try:
            return payload.decode(enc, errors="strict")
        except Exception:
            continue
    return payload.decode("utf-8", errors="replace")
