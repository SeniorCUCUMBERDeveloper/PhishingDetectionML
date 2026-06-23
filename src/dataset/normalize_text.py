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
    _WEB_SCHEME_RE,
    _WS_RE,
)
from scrub_corpus_artifacts import scrub_corpus_artifacts
from strip_html import _strip_html


def _normalize_text(plain_parts: list[str], html_parts: list[str]) -> tuple[str, bool]:
    html_links: list[str] = []
    if plain_parts:
        text = "\n".join(plain_parts)
        for h in html_parts:
            _, links = _strip_html(h)
            html_links.extend(links)
    elif html_parts:
        chunks = []
        for h in html_parts:
            visible, links = _strip_html(h)
            chunks.append(visible)
            html_links.extend(links)
        text = "\n".join(chunks)
    else:
        text = ""

    has_url = (bool(_URL_RE.search(text)) or bool(_URL_SCHEME_SPACED_RE.search(text))
               or bool(_URL_SPACED_RE.search(text))
               or any(_WEB_SCHEME_RE.search(l) for l in html_links))

    text = _URL_RE.sub(" ", text)
    text = _URL_SCHEME_SPACED_RE.sub(" ", text)
    text = _URL_SPACED_RE.sub(" ", text)
    text = _html.unescape(text)
    text = scrub_corpus_artifacts(text)
    text = _WS_RE.sub(" ", text).strip()
    return text, has_url
