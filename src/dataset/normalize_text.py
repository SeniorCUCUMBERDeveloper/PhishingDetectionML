#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import html as _html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regexes import (
    _URL_RE,
    _URL_SCHEME_SPACED_RE,
    _URL_SPACED_RE,
    _WS_RE,
)
from scrub_corpus_artifacts import scrub_corpus_artifacts
from strip_html import _strip_html


def _normalize_text(plain_parts: list[str], html_parts: list[str]) -> str:
    if plain_parts:
        text = "\n".join(plain_parts)
    elif html_parts:
        text = "\n".join(_strip_html(h)[0] for h in html_parts)
    else:
        text = ""

    text = _URL_RE.sub(" ", text)
    text = _URL_SCHEME_SPACED_RE.sub(" ", text)
    text = _URL_SPACED_RE.sub(" ", text)
    text = _html.unescape(text)
    text = scrub_corpus_artifacts(text)
    text = _WS_RE.sub(" ", text).strip()
    return text