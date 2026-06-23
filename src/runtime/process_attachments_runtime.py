#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import os
import sys
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_qr_urls import _decode_qr_urls
from is_attachment import _is_attachment
from soft_deps import _HAVE_QR


def _process_attachments_runtime(msg: EmailMessage) -> tuple[bool, list[str], list[dict]]:
    has_attachment = False
    qr_urls: list[str] = []
    attachments: list[dict] = []

    for part in msg.walk():
        if part.is_multipart() or not _is_attachment(part):
            continue
        has_attachment = True
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        content_type = (part.get_content_type() or "").lower()
        attachments.append({
            "filename": part.get_filename(),
            "content_type": content_type,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            "md5": hashlib.md5(payload).hexdigest() if payload else None,
        })
        if _HAVE_QR and payload and content_type.startswith("image/"):
            qr_urls.extend(_decode_qr_urls(payload))

    return has_attachment, sorted(set(qr_urls)), attachments
