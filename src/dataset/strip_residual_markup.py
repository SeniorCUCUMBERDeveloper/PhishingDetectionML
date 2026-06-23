#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import re

_B64 = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')

_CSS_BLOCK = re.compile(r'[.#]?[A-Za-z][\w-]*\s*\{[^{}]{0,600}\}')

_HTML_TAG = re.compile(r'<[^<>]{0,400}>')

_HTML_ATTR = re.compile(r'\b[a-z][\w-]*\s*=\s*"[^"]{0,200}"', re.I)

_CSS_PROP = re.compile(
    r'\b(?:font-size|font-family|line-height|padding|margin|background|border|'
    r'cellpadding|cellspacing|valign|text-align|font-weight|width|height)'
    r'\s*[:=]\s*[^;{}\n,"]{0,40};?', re.I)


def strip_residual_markup(text: str) -> str:
    if not text:
        return text
    text = _B64.sub(' ', text)
    text = _CSS_BLOCK.sub(' ', text)
    for _ in range(2):
        text = _HTML_TAG.sub(' ', text)
    text = _HTML_ATTR.sub(' ', text)
    text = _CSS_PROP.sub(' ', text)
    return text
