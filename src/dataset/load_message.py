#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from email import message_from_bytes, policy
from email.message import EmailMessage
from pathlib import Path
from typing import Union


def _load_message(src: Union[str, Path, bytes]) -> EmailMessage:
    if isinstance(src, (bytes, bytearray)):
        raw = bytes(src)
    else:
        raw = Path(src).read_bytes()
    return message_from_bytes(raw, policy=policy.default)
