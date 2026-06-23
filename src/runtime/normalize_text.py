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


def _normalize_text(plain_parts: list[str], html_parts: list[str]) -> tuple[str, bool, list[str]]:
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

    all_urls: set[str] = set()

    all_urls.update(l for l in html_links if _WEB_SCHEME_RE.search(l))

    all_urls.update(m.group(0) for m in _URL_RE.finditer(text))

    for rx in (_URL_SCHEME_SPACED_RE, _URL_SPACED_RE):
        for m in rx.finditer(text):
            all_urls.add(_WS_RE.sub("", m.group(0)))
    all_urls = {_html.unescape(u) for u in all_urls if u}
    has_url = bool(all_urls)

    text = _URL_RE.sub(" ", text)
    text = _URL_SCHEME_SPACED_RE.sub(" ", text)
    text = _URL_SPACED_RE.sub(" ", text)
    text = _html.unescape(text)
    text = scrub_corpus_artifacts(text)
    text = _WS_RE.sub(" ", text).strip()
    return text, has_url, sorted(all_urls)
