#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re

I, M = re.IGNORECASE, re.MULTILINE

_ARTIFACT_TOKENS = (

    "enron", "ect", "hou",

    "sourceforge", "exmh", "spamassassin", "razor", "freshrpms", "xent", "zzzteana",
)
_ARTIFACT_TOKEN_RE = re.compile(r"\b(?:" + "|".join(_ARTIFACT_TOKENS) + r")\b", I)
_ARTIFACT_DOMAIN_RE = re.compile(
    r"\b(?:enron\.com|lists\.sourceforge\.net|sourceforge\.net)\b", I)


def scrub_corpus_tokens(text: str) -> str:
    text = _ARTIFACT_DOMAIN_RE.sub(" ", text)
    text = _ARTIFACT_TOKEN_RE.sub(" ", text)
    return text
