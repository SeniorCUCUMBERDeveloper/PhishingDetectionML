#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from strip_residual_markup import strip_residual_markup
from normalize_delivery_artifacts import normalize_delivery_artifacts
from scrub_corpus_tokens import scrub_corpus_tokens


def scrub_corpus_artifacts(text: str) -> str:
    if not text:
        return text
    text = strip_residual_markup(text)
    text = normalize_delivery_artifacts(text)
    text = scrub_corpus_tokens(text)
    return text