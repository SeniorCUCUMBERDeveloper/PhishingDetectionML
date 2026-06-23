#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional, Union

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth_results import _auth_results
from epi_fields import _EPI_FIELDS
from extract_bodies import _extract_bodies
from header import _header
from load_message import _load_message
from normalize_text import _normalize_text
from process_attachments import _process_attachments


def email_to_epi(
    src: Union[str, Path, bytes],
    *,
    id: Optional[str] = None,
    source: Optional[str] = None,
    label: Optional[str] = None,
    split: Optional[str] = None,
) -> dict[str, Any]:
    msg = _load_message(src)

    record: dict[str, Any] = {
        "id": id,
        "text": None,
        "label": label,
        "source": source,
        "split": split,
        "from": _header(msg, "From"),
        "reply_to": _header(msg, "Reply-To"),
        "return_path": _header(msg, "Return-Path"),
        "subject": _header(msg, "Subject"),
        "message_id": _header(msg, "Message-ID"),
        "in_reply_to": _header(msg, "In-Reply-To"),
        "references": _header(msg, "References"),
        "auth_results": _auth_results(msg),
    }

    plain_parts, html_parts = _extract_bodies(msg)
    text, has_url = _normalize_text(plain_parts, html_parts)
    record["text"] = text

    has_attachment, has_qr, qr_url = _process_attachments(msg)

    record["has_url"] = bool(has_url or qr_url)
    record["has_qr"] = bool(has_qr)
    record["has_attachment"] = bool(has_attachment)

    return {k: record.get(k) for k in _EPI_FIELDS}


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="EML -> облегчённый ЕПИ (JSON). Keystone-предобработка этапа 2 (FR3)."
    )
    parser.add_argument("eml", help="путь к .eml-файлу (или - для чтения stdin как байтов)")
    parser.add_argument("--source", default=None, help="происхождение письма (nazario|spamassassin|enron|...)")
    parser.add_argument("--label", default=None, help="метка (phishing|legitimate)")
    parser.add_argument("--split", default=None, help="часть выборки (train|val|test)")
    parser.add_argument("--id", default=None, help="идентификатор письма")
    args = parser.parse_args(argv)

    if args.eml == "-":
        src: Union[bytes, str] = sys.stdin.buffer.read()
    else:
        src = args.eml

    epi = email_to_epi(src, id=args.id, source=args.source, label=args.label, split=args.split)
    print(json.dumps(epi, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(_main())
