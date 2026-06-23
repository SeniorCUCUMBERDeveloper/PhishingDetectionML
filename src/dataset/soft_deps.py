#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

try:
    from bs4 import BeautifulSoup
    _HAVE_BS4 = True
except Exception:
    BeautifulSoup = None
    _HAVE_BS4 = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as _qr_decode
    _HAVE_QR = True
except Exception:
    Image = None
    _qr_decode = None
    _HAVE_QR = False
