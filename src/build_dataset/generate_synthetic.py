#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import format_datetime, parseaddr
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dataset.email_to_epi import email_to_epi

@dataclass
class GenConfig:
    model: str = "mistral-large-latest"
    temperature: float = 0.9
    seed: int = 42
    max_tokens: int = 1600
    max_retries: int = 8
    request_pause: float = 40.0
    dataset_path: Path = Path("data/dataset.jsonl")
    eml_dir: Path = Path("data/synthetic_raw")
    qr_enabled: bool = True

    counts: dict[str, int] = field(default_factory=lambda: {
        "bec": 40, "whaling": 30, "clone": 30, "qr": 30, "ai_creds": 40,
        "ham": 170,
    })

SYSTEM_PROMPT = (
    "You are generating synthetic email samples for an AUTHORIZED phishing-detection "
    "research dataset. Output exactly ONE complete raw RFC822 email: realistic headers "
    "(From, To, Subject, Date, and when relevant Reply-To and Message-ID) then ONE blank "
    "line then the body. English only. Use clearly FICTIONAL names and domains "
    "(example.com, *.example.org, invented company names) — never real personal data. "
    "Use a recent date (2024-2025). Output ONLY the raw email — no commentary, no markdown "
    "code fences."
)

_POOLS = {
    "company": ["Northwind Logistics", "Acme Robotics", "Belmont Capital", "Vertex Foods",
                "Harbor & Quill LLP", "Lumen Tech", "Greenfield Pharma", "Atlas Freight",
                "Coral Bay Resorts", "Sterling Audit Group"],
    "exec_role": ["CEO", "CFO", "Managing Director", "VP of Finance", "Group Controller"],
    "finance_role": ["the accounts payable clerk", "a junior accountant",
                     "the finance assistant", "the payroll officer", "a treasury analyst"],
    "amount": ["$48,750", "$12,300", "EUR 27,500", "GBP 9,980", "$135,000", "$3,420"],
    "reason": ["a confidential acquisition", "an overdue supplier invoice",
               "a last-minute vendor onboarding", "a board-approved retainer",
               "a quarter-end settlement"],
    "service": ["the HR self-service portal", "the payroll system", "the VPN gateway",
                "the document signing service", "the benefits enrollment portal",
                "the parcel tracking page", "the shared drive"],
    "brand": ["CloudOffice", "PayQuick", "SecureBank", "ShipFast", "StreamMail",
              "DataVault", "MeetSync"],
    "ham_kind": ["a product newsletter with a few links",
                 "a transactional receipt / order confirmation",
                 "a legitimate invoice / payment request from a known vendor",
                 "a subscription renewal reminder",
                 "a shipping/delivery status update",
                 "a password-change confirmation (informational, no action link)"],
    "topic": ["the Q3 budget", "the vendor contract", "the project timeline",
              "the audit findings", "the staffing plan"],
}


def _pick(rng: random.Random, key: str) -> str:
    return rng.choice(_POOLS[key])


def _user_prompt(spec_key: str, rng: random.Random) -> str:
    if spec_key == "bec":
        return (
            f"Write a Business Email Compromise (BEC) phishing email (class III: financial-"
            f"procedural). A sender impersonating the {_pick(rng,'exec_role')} of "
            f"{_pick(rng,'company')} urgently instructs {_pick(rng,'finance_role')} to process "
            f"an urgent wire transfer of {_pick(rng,'amount')} to a new beneficiary OR to update "
            f"the bank account details for an upcoming payment. Pretext: {_pick(rng,'reason')}. "
            f"Tone: professional, concise; pressure for speed and confidentiality. Group C signals "
            f"(payment / change of banking details, urgency, executive imitation). Headers must be "
            f"internally consistent (From and any Reply-To share the same corporate domain). Do NOT "
            f"include a QR code. Links optional. No spelling errors."
        )
    if spec_key == "whaling":
        return (
            f"Write a whaling phishing email (class III) targeting a senior executive "
            f"({_pick(rng,'exec_role')}) of {_pick(rng,'company')}. The message impersonates an "
            f"external trusted party (lawyer, auditor, or key supplier) and pushes the executive to "
            f"authorize a payment of {_pick(rng,'amount')} or change payment details, citing "
            f"{_pick(rng,'reason')}. Formal, high-stakes, time-pressured tone. Group C (payment / "
            f"change of details, urgency). Internally consistent headers, same domain for From/"
            f"Reply-To. No QR code. No spelling errors."
        )
    if spec_key == "clone":
        return (
            f"Write a clone-style phishing email (class I: imitation of legitimate communication) "
            f"that pretends to CONTINUE an existing thread about {_pick(rng,'topic')} at "
            f"{_pick(rng,'company')}. The subject should read like a reply (it will be forced to "
            f"'Re:'). The body quotes/paraphrases a prior message and asks the recipient to review "
            f"an updated document or confirm details. Keep it plausible and businesslike."
        )
    if spec_key == "qr":
        return (
            f"Write a phishing email (class II: QR scenario) that asks the recipient to scan a QR "
            f"code to access {_pick(rng,'service')} (e.g. re-activate access, confirm identity, view "
            f"a secure document). PLAIN TEXT body only (no HTML). Reference the QR code in the body "
            f"('scan the QR code below'). Do NOT paste any URL in the text — the QR image is attached "
            f"separately. Headers internally consistent. No spelling errors."
        )
    if spec_key == "ai_creds":
        return (
            f"Write a polished, convincing credential-phishing email (class IV) impersonating "
            f"{_pick(rng,'brand')}. It warns about unusual sign-in activity or a required security "
            f"verification and urges the user to confirm their account via a verification link. "
            f"Include exactly one plausible verification link (use a fictional domain like "
            f"https://account-verify.example-login.com/secure). Fluent, no grammatical errors, no "
            f"obvious red flags. Group C (urgency, credential request) + a link (group W)."
        )
    if spec_key == "ham":
        return (
            f"Write an ORDINARY, modern, fully LEGITIMATE email of this kind: "
            f"{_pick(rng,'ham_kind')} from {_pick(rng,'brand')} or {_pick(rng,'company')}. "
            f"It should be a routine, harmless message — an informational newsletter, an order or "
            f"delivery confirmation, a subscription notice, an account statement, a receipt, or an "
            f"announcement — that simply INFORMS the recipient. Calm, neutral tone; no pressure.\n"
            f"This is a 'hard but honest' legitimate email: it may share a topic with transactional "
            f"mail, but it must contain NONE of the following phishing-like traits.\n"
            f"STRICTLY FORBIDDEN (do not include any of these):\n"
            f"- any request to verify, confirm, update, or enter credentials, passwords, login "
            f"details, or payment/bank details via a link;\n"
            f"- any threat, account-suspension warning, or fear-based deadline "
            f"(e.g. 'within 24 hours or your account will be blocked/lost');\n"
            f"- the phrases 'verify your account', 'verify your details', 'secure link', "
            f"'immediate action required', or any equivalent coercion to act on personal data.\n"
            f"REQUIREMENTS:\n"
            f"- if you include a link, it must point to an ordinary page (the order, an article, a "
            f"product page, a help article) — NOT a login, sign-in, 'verify', or 'secure' page;\n"
            f"- no urgency or pressure to act with personal/payment data;\n"
            f"- consistent, genuine sender identity. Modern style. No spelling errors."
        )
    raise ValueError(f"unknown spec: {spec_key}")

SPEC_META = {
    "bec":      ("phishing",    "plain"),
    "whaling":  ("phishing",    "plain"),
    "clone":    ("phishing",    "clone"),
    "qr":       ("phishing",    "qr"),
    "ai_creds": ("phishing",    "plain"),
    "ham":      ("legitimate",  "plain"),
}


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def _other_domain(addr: str) -> str:
    return "secure-account-update.example.net"


def _enforce_clone_headers(raw: bytes, recent_date: str) -> bytes:
    msg = message_from_bytes(raw, policy=policy.default)
    subj = str(msg["Subject"] or "document review")
    if not re.match(r"(?i)^\s*(re|fwd?)\b", subj):
        del msg["Subject"]
        msg["Subject"] = "Re: " + subj
    frm = parseaddr(str(msg["From"] or ""))[1]
    if frm and "@" in frm:
        del msg["Reply-To"]
        msg["Reply-To"] = f"reply@{_other_domain(frm)}"
    for h in ("In-Reply-To", "References"):
        del msg[h]
    if not msg["Date"]:
        msg["Date"] = recent_date
    return msg.as_bytes()


def _build_qr_png(data: str) -> Optional[bytes]:
    try:
        import io
        import qrcode
        img = qrcode.make(data)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


def _attach_qr(raw: bytes, url: str, recent_date: str) -> bytes:
    png = _build_qr_png(url)
    if png is None:
        return raw
    src = message_from_bytes(raw, policy=policy.default)
    out = EmailMessage()
    for h in ("From", "To", "Subject", "Reply-To", "Message-ID"):
        if src[h]:
            out[h] = str(src[h])
    out["Date"] = str(src["Date"]) if src["Date"] else recent_date

    try:
        body = src.get_body(preferencelist=("plain", "html"))
        text = body.get_content() if body else src.get_content()
    except Exception:
        text = src.get_payload(decode=True) or b""
        text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    out.set_content(text)
    out.add_attachment(png, maintype="image", subtype="png", filename="qr-code.png")
    return out.as_bytes()


def _finalize_raw(spec_key: str, raw_text: str, rng: random.Random, recent_date: str) -> bytes:
    raw = _strip_fences(raw_text).encode("utf-8")
    kind = SPEC_META[spec_key][1]
    if kind == "clone":
        return _enforce_clone_headers(raw, recent_date)
    if kind == "qr":
        url = f"https://{_pick(rng,'brand').lower()}.example-verify.org/q/{rng.randrange(10**6):06d}"
        return _attach_qr(raw, url, recent_date)
    return raw


def _make_client(cfg: GenConfig):
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise SystemExit("Не задан MISTRAL_API_KEY (экспортируйте переменную окружения).")
    from mistralai.client import Mistral
    return Mistral(api_key=api_key)


def _status_code(exc: Exception) -> Optional[int]:
    for attr in ("status_code", "status", "http_status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int):
            return v
    resp = getattr(exc, "response", None) or getattr(exc, "raw_response", None)
    if resp is not None and isinstance(getattr(resp, "status_code", None), int):
        return resp.status_code
    m = re.search(r"\b([45]\d{2})\b", str(exc))
    return int(m.group(1)) if m else None


def _retryable(code: Optional[int]) -> bool:
    return code == 429 or (code is not None and 500 <= code < 600) or code is None


def _retry_after(exc: Exception) -> Optional[float]:
    resp = getattr(exc, "raw_response", None) or getattr(exc, "response", None)
    headers = getattr(resp, "headers", None) or getattr(exc, "headers", None)
    if headers is None:
        return None
    try:
        val = headers.get("Retry-After") or headers.get("retry-after")
    except Exception:
        val = None
    if not val:
        return None
    val = str(val).strip()
    try:
        return max(0.0, float(val))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(val)
        if dt is not None:
            return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        pass
    return None


def _complete(client, cfg: GenConfig, messages: list[dict], rseed: int,
              errors: Optional[dict] = None) -> str:
    last_err = None
    for attempt in range(cfg.max_retries):
        try:
            res = client.chat.complete(
                model=cfg.model, messages=messages,
                temperature=cfg.temperature, max_tokens=cfg.max_tokens,
                random_seed=rseed,
            )
            return res.choices[0].message.content
        except Exception as e:
            last_err = e
            code = _status_code(e)
            key = str(code) if code is not None else type(e).__name__
            if errors is not None:
                errors[key] = errors.get(key, 0) + 1

            if not _retryable(code) or attempt == cfg.max_retries - 1:
                break

            wait = _retry_after(e) if code == 429 else None
            if wait is None:
                wait = 2 ** attempt
            time.sleep(wait)
    raise RuntimeError(
        f"Mistral API не ответил (последний код {_status_code(last_err)}): {last_err}")


def _recent_date(rng: random.Random) -> str:
    base = datetime(2025, 6, 1, tzinfo=timezone.utc)
    dt = base - timedelta(days=rng.randrange(0, 365), seconds=rng.randrange(0, 86400))
    return format_datetime(dt)


def _load_existing_ids(dataset_path: Path) -> set[str]:
    ids: set[str] = set()
    if dataset_path.exists():
        with dataset_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ids.add(json.loads(line)["id"])
                    except Exception:
                        continue
    return ids


def run(cfg: GenConfig, complete_fn: Optional[Callable[[list, int], str]] = None,
        dry_run: bool = False, limit_per_class: int = 0) -> dict:
    existing_ids = _load_existing_ids(cfg.dataset_path)
    seen = set(existing_ids)

    stats = {
        "generated": {}, "accepted": {}, "dropped_dup": 0, "dropped_empty": 0,
        "failed": 0, "by_label": {"phishing": 0, "legitimate": 0},
        "errors": {},
        "synth_text_lens": [], "model": cfg.model, "seed": cfg.seed,
    }

    throttle = cfg.request_pause if complete_fn is None else 0.0
    if complete_fn is None:
        client = _make_client(cfg)
        complete_fn = lambda messages, rseed: _complete(client, cfg, messages, rseed,
                                                        errors=stats["errors"])

    accepted_records: list[dict] = []
    counter = 0

    for spec_key, count in cfg.counts.items():
        if limit_per_class:
            count = min(count, limit_per_class)
        label = SPEC_META[spec_key][0]
        stats["generated"][spec_key] = 0
        stats["accepted"][spec_key] = 0

        for i in range(count):
            counter += 1
            rng = random.Random(f"{cfg.seed}:{spec_key}:{i}")
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(spec_key, rng)},
            ]
            if throttle and counter > 1:
                time.sleep(throttle)
            try:
                raw_text = complete_fn(messages, cfg.seed + counter)
            except Exception:
                stats["failed"] += 1
                continue
            stats["generated"][spec_key] += 1

            recent = _recent_date(rng)
            raw_bytes = _finalize_raw(spec_key, raw_text, rng, recent)

            eml_path = cfg.eml_dir / spec_key / f"{i:04d}.eml"
            eml_path.parent.mkdir(parents=True, exist_ok=True)
            eml_path.write_bytes(raw_bytes)

            try:
                rec = email_to_epi(raw_bytes, source="synthetic", label=label, split="train")
            except Exception:
                stats["failed"] += 1
                continue

            text = (rec.get("text") or "").strip()
            if not text:
                stats["dropped_empty"] += 1
                continue
            h = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if h in seen:
                stats["dropped_dup"] += 1
                continue
            seen.add(h)
            rec["id"] = h

            accepted_records.append(rec)
            stats["accepted"][spec_key] += 1
            stats["by_label"][label] += 1
            stats["synth_text_lens"].append(len(text))

    if not dry_run and accepted_records:
        cfg.dataset_path.parent.mkdir(parents=True, exist_ok=True)
        with cfg.dataset_path.open("a", encoding="utf-8") as f:
            for rec in accepted_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    _write_manifest(cfg, stats, dry_run)
    return stats


def _write_manifest(cfg: GenConfig, stats: dict, dry_run: bool) -> None:
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "model": cfg.model, "temperature": cfg.temperature, "seed": cfg.seed,
        "max_tokens": cfg.max_tokens, "qr_enabled": cfg.qr_enabled,
        "request_pause": cfg.request_pause, "max_retries": cfg.max_retries,
        "counts_requested": cfg.counts,
        "system_prompt": SYSTEM_PROMPT,
        "results": {k: v for k, v in stats.items() if k != "synth_text_lens"},
    }
    cfg.eml_dir.mkdir(parents=True, exist_ok=True)
    (cfg.eml_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def import_from_raw(cfg: GenConfig, dry_run: bool = False) -> dict:
    existing_ids = _load_existing_ids(cfg.dataset_path)
    seen = set(existing_ids)
    stats = {
        "generated": {}, "accepted": {}, "dropped_dup": 0, "dropped_empty": 0,
        "failed": 0, "by_label": {"phishing": 0, "legitimate": 0},
        "errors": {}, "synth_text_lens": [],
        "model": "(from-raw, без Mistral)", "seed": cfg.seed,
    }
    accepted_records: list[dict] = []

    for spec_key, (label, _kind) in SPEC_META.items():
        stats["generated"][spec_key] = 0
        stats["accepted"][spec_key] = 0
        cls_dir = cfg.eml_dir / spec_key
        if not cls_dir.is_dir():
            continue
        for eml_path in sorted(cls_dir.glob("*.eml")):
            stats["generated"][spec_key] += 1
            try:
                raw_bytes = eml_path.read_bytes()
                rec = email_to_epi(raw_bytes, source="synthetic", label=label, split="train")
            except Exception:
                stats["failed"] += 1
                continue
            text = (rec.get("text") or "").strip()
            if not text:
                stats["dropped_empty"] += 1
                continue
            h = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if h in seen:
                stats["dropped_dup"] += 1
                continue
            seen.add(h)
            rec["id"] = h
            accepted_records.append(rec)
            stats["accepted"][spec_key] += 1
            stats["by_label"][label] += 1
            stats["synth_text_lens"].append(len(text))

    if not dry_run and accepted_records:
        cfg.dataset_path.parent.mkdir(parents=True, exist_ok=True)
        with cfg.dataset_path.open("a", encoding="utf-8") as f:
            for rec in accepted_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return stats


def _median(xs: list[int]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    return float(s[n // 2]) if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def _real_text_lens(dataset_path: Path) -> list[int]:
    lens: list[int] = []
    if not dataset_path.exists():
        return lens
    with dataset_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("source") != "synthetic" and r.get("text"):
                lens.append(len(r["text"]))
    return lens


def _print_stats(cfg: GenConfig, stats: dict, dry_run: bool) -> None:
    print(f"\n=== Синтетика {'(DRY-RUN, в датасет не записано)' if dry_run else ''} ===")
    print(f"Модель: {stats['model']} | seed: {stats['seed']}")
    print("Принято по классам (сгенерировано):")
    for k in cfg.counts:
        print(f"  {k:10s} {stats['accepted'].get(k,0):4d}  (из {stats['generated'].get(k,0)})")
    print("Принято по метке:")
    for lbl, n in stats["by_label"].items():
        print(f"  {lbl:12s} {n}")
    print(f"Отброшено дедупом: {stats['dropped_dup']} | пустых: {stats['dropped_empty']} "
          f"| ошибок API/парсинга: {stats['failed']}")
    if stats.get("errors"):
        codes = ", ".join(f"{k}: {v}" for k, v in sorted(stats["errors"].items()))
        print(f"Неуспешные попытки Mistral (код: число): {codes}")

    syn = stats["synth_text_lens"]
    real = _real_text_lens(cfg.dataset_path)
    print("\nСверка длины text (символов):")
    print(f"  синтетика: n={len(syn):4d}  mean={ (sum(syn)/len(syn) if syn else 0):.0f}  "
          f"median={_median(syn):.0f}")
    print(f"  реальные:  n={len(real):4d}  mean={ (sum(real)/len(real) if real else 0):.0f}  "
          f"median={_median(real):.0f}")


def _main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Генерация синтетики (Mistral) -> train часть dataset.jsonl")
    p.add_argument("--dataset", default="data/dataset.jsonl")
    p.add_argument("--eml-dir", default="data/synthetic_raw")
    p.add_argument("--model", default=GenConfig.model)
    p.add_argument("--temperature", type=float, default=GenConfig.temperature)
    p.add_argument("--seed", type=int, default=GenConfig.seed)
    p.add_argument("--max-tokens", type=int, default=GenConfig.max_tokens)
    p.add_argument("--no-qr", action="store_true", help="не вкладывать PNG QR (QR-письма текстом)")
    p.add_argument("--limit-per-class", type=int, default=0, help="ограничить число писем на класс (тест)")
    p.add_argument("--dry-run", action="store_true", help="сгенерировать, но НЕ дозаписывать в датасет")
    p.add_argument("--from-raw", action="store_true",
                   help="повторный импорт готовых .eml из --eml-dir БЕЗ вызова Mistral")
    args = p.parse_args(argv)

    cfg = GenConfig(
        model=args.model, temperature=args.temperature, seed=args.seed,
        max_tokens=args.max_tokens, dataset_path=Path(args.dataset),
        eml_dir=Path(args.eml_dir), qr_enabled=not args.no_qr,
    )
    if args.from_raw:
        stats = import_from_raw(cfg, dry_run=args.dry_run)
    else:
        stats = run(cfg, dry_run=args.dry_run, limit_per_class=args.limit_per_class)
    _print_stats(cfg, stats, args.dry_run)
    return 0

if __name__ == "__main__":
    raise SystemExit(_main())
