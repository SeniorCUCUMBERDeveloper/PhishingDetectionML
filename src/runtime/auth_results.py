#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
from email.message import EmailMessage
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regexes import _WS_RE


def _auth_results(msg: EmailMessage) -> Optional[str]:
    values = msg.get_all("Authentication-Results")
    if not values:
        return None
    parts = []
    for v in values:
        try:
            s = _WS_RE.sub(" ", str(v)).strip()
        except Exception:
            continue
        if s:
            parts.append(s)
    return " | ".join(parts) if parts else None
