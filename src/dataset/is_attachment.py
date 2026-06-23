#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from email.message import EmailMessage


def _is_attachment(part: EmailMessage) -> bool:
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    if part.get_filename():
        return True
    return False
