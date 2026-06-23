#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from is_attachment import _is_attachment
from soft_deps import _HAVE_QR
from try_decode_qr import _try_decode_qr


def _process_attachments(msg: EmailMessage) -> tuple[bool, bool, bool]:
    has_attachment = False
    has_qr = False
    qr_contains_url = False

    for part in msg.walk():
        if part.is_multipart() or not _is_attachment(part):
            continue
        has_attachment = True
        content_type = (part.get_content_type() or "").lower()
        if _HAVE_QR and content_type.startswith("image/"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            if payload:
                found, has_link = _try_decode_qr(payload)
                if found:
                    has_qr = True
                    qr_contains_url = qr_contains_url or has_link

    return has_attachment, has_qr, qr_contains_url
