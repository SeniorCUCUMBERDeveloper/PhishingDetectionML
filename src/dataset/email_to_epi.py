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
from extract_bodies import _extract_bodies
from header import _header
from load_message import _load_message
from normalize_text import _normalize_text


def email_to_epi(
    src: Union[str, Path, bytes],
    *,
    id: Optional[str] = None,
    source: Optional[str] = None,
    label: Optional[str] = None,
    split: Optional[str] = None,
) -> dict[str, Any]:
    msg = _load_message(src)
    plain_parts, html_parts = _extract_bodies(msg)
    text = _normalize_text(plain_parts, html_parts)

    return {

        "id": id,
        "text": text,
        "label": label,
        "source": source,
        "split": split,

        "from": _header(msg, "From"),
        "subject": _header(msg, "Subject"),
        "message_id": _header(msg, "Message-ID"),
        "in_reply_to": _header(msg, "In-Reply-To"),
        "references": _header(msg, "References"),
    }


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="EML -> запись выборки (JSON). Keystone-предобработка этапа 2 (FR3)."
    )
    parser.add_argument("eml", help="путь к .eml-файлу (или - для чтения stdin как байтов)")
    parser.add_argument("--source", default=None, help="происхождение (enron|spamassassin|...)")
    parser.add_argument("--label", default=None, help="метка (phishing|legitimate)")
    parser.add_argument("--split", default=None, help="часть выборки (train|val|test)")
    parser.add_argument("--id", default=None, help="идентификатор письма")
    args = parser.parse_args(argv)

    src: Union[bytes, str] = sys.stdin.buffer.read() if args.eml == "-" else args.eml
    rec = email_to_epi(src, id=args.id, source=args.source, label=args.label, split=args.split)
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(_main())
