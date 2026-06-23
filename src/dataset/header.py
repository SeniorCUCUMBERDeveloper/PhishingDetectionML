#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
from email.header import decode_header, make_header
from email.message import EmailMessage
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regexes import _WS_RE


def _header(msg: EmailMessage, name: str) -> Optional[str]:
    raw = msg.get(name)
    if raw is None:
        return None
    try:
        value = str(raw)
    except Exception:
        try:
            value = str(make_header(decode_header(str(raw))))
        except Exception:
            return None
    value = _WS_RE.sub(" ", value).strip()
    return value or None
