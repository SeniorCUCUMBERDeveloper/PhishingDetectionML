#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regexes import _URL_RE, _WEB_SCHEME_RE
from soft_deps import Image, _qr_decode


def _decode_qr_urls(payload: bytes) -> list[str]:
    urls: list[str] = []
    try:
        import io
        img = Image.open(io.BytesIO(payload))
        for r in _qr_decode(img):
            try:
                data = r.data.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if _WEB_SCHEME_RE.search(data) or _URL_RE.search(data):
                urls.append(data)
    except Exception:
        pass
    return urls
