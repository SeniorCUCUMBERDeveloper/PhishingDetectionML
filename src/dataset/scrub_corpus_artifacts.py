#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_delivery_artifacts import normalize_delivery_artifacts
from scrub_corpus_tokens import scrub_corpus_tokens


def scrub_corpus_artifacts(text: str) -> str:
    if not text:
        return text
    text = normalize_delivery_artifacts(text)
    text = scrub_corpus_tokens(text)
    return text
