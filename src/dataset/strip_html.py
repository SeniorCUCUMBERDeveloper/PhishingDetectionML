#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import html as _html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regexes import _ATTR_LINK_RE, _SCRIPT_STYLE_RE, _TAG_RE
from soft_deps import _HAVE_BS4, BeautifulSoup


def _strip_html(html_text: str) -> tuple[str, list[str]]:
    links: list[str] = []
    if _HAVE_BS4:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for tag, attr in (("a", "href"), ("area", "href"), ("img", "src"),
                              ("form", "action"), ("source", "src"), ("iframe", "src")):
                for el in soup.find_all(tag):
                    val = el.get(attr)
                    if val:
                        links.append(val.strip())
            for el in soup(["script", "style"]):
                el.decompose()
            text = soup.get_text(separator=" ")
            return text, links
        except Exception:
            pass
    for m in _ATTR_LINK_RE.finditer(html_text):
        val = m.group(1) or m.group(2) or m.group(3)
        if val:
            links.append(val.strip())
    text = _SCRIPT_STYLE_RE.sub(" ", html_text)
    text = _TAG_RE.sub(" ", text)
    text = _html.unescape(text)
    return text, links
