#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

try:
    from bs4 import BeautifulSoup
    _HAVE_BS4 = True
except Exception:
    BeautifulSoup = None
    _HAVE_BS4 = False