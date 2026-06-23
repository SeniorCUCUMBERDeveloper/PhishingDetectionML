#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re


def _to_live_url(url: str) -> str:
    u = url.strip()
    u = re.sub(r"(?i)^hxxp", "http", u)
    u = re.sub(r"(?i)^fxp", "ftp", u)
    u = u.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    return u
