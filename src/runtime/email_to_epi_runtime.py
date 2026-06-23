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
from extract_bodies import _extract_bodies
from header import _header
from load_message import _load_message
from normalize_text import _normalize_text
from process_attachments_runtime import _process_attachments_runtime
from runtime_epi_fields import _RUNTIME_EPI_FIELDS
from to_live_url import _to_live_url


def email_to_epi_runtime(
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
    text, has_url, all_urls = _normalize_text(plain_parts, html_parts)
    record["text"] = text

    has_attachment, qr_urls, attachments = _process_attachments_runtime(msg)

    record["urls"] = sorted({_to_live_url(u) for u in (all_urls + qr_urls) if u})
    record["attachments"] = attachments
    record["has_url"] = bool(has_url or qr_urls)
    record["has_qr"] = bool(qr_urls)
    record["has_attachment"] = bool(has_attachment)

    return {k: record.get(k) for k in _RUNTIME_EPI_FIELDS}


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="EML -> ПОЛНОЕ ЕПИ (JSON). Рантайм-предобработка детектора (этапы 3–4)."
    )
    parser.add_argument("eml", help="путь к .eml-файлу (или - для чтения stdin как байтов)")
    parser.add_argument("--source", default=None, help="происхождение письма")
    parser.add_argument("--label", default=None, help="метка (phishing|legitimate)")
    parser.add_argument("--split", default=None, help="часть выборки (train|val|test)")
    parser.add_argument("--id", default=None, help="идентификатор письма")
    args = parser.parse_args(argv)

    if args.eml == "-":
        src: Union[bytes, str] = sys.stdin.buffer.read()
    else:
        src = args.eml

    epi = email_to_epi_runtime(src, id=args.id, source=args.source,
                               label=args.label, split=args.split)
    print(json.dumps(epi, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(_main())
