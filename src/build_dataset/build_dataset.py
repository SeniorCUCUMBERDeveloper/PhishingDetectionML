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
from email.utils import getaddresses
from pathlib import Path
from typing import Iterable, Iterator, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dataset.email_to_epi import email_to_epi

try:
    from langdetect import DetectorFactory, LangDetectException, detect
    DetectorFactory.seed = 0
    _HAVE_LANGDETECT = True
except Exception:
    _HAVE_LANGDETECT = False

try:
    from datasketch import MinHash, MinHashLSH
    _HAVE_DATASKETCH = True
except Exception:
    _HAVE_DATASKETCH = False

SOURCE_LABELS = {
    "phishing_pot": "phishing",
    "nazario": "phishing",
    "spamassassin": "legitimate",
    "enron": "legitimate",
}

DEFAULT_SEED = 42
DEFAULT_ENRON_SAMPLE = 3000
VAL_FRAC, TEST_FRAC = 0.10, 0.10
TARGET_LANG = "en"

NEAR_THRESHOLD = 0.8
NEAR_NUM_PERM = 128
NEAR_SHINGLE_K = 5
NEAR_MAX_CLUSTER = 0

OUTPUT_FIELDS = ("id", "text", "label", "source", "split")

_MBOX_SEP = re.compile(rb"(?m)^From \S+.*?\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b.*$")

_HEADER_LINE = re.compile(rb"(?m)^[A-Za-z][A-Za-z0-9-]{0,40}:[ \t]")

_MSGID = re.compile(r"<[^<>\s]+>")

_REPLY_PREFIX = re.compile(r"^\s*(?:re|fwd?|aw|wg|sv|vs|rv|rif|tr|fyi)\s*(?:\[\d+\])?\s*:\s*", re.I)
_WS = re.compile(r"\s+")


def _looks_like_email(raw: bytes) -> bool:
    head = raw[:4096]
    return len(_HEADER_LINE.findall(head)) >= 2


def _is_mbox(raw: bytes, path: Path) -> bool:
    if path.suffix.lower() == ".mbox":
        return True
    seps = list(_MBOX_SEP.finditer(raw))
    return len(seps) >= 2 and seps[0].start() == 0


def iter_message_bytes(path: Path) -> Iterator[bytes]:
    try:
        raw = path.read_bytes()
    except Exception:
        return
    if not raw.strip():
        return
    if _is_mbox(raw, path):
        seps = list(_MBOX_SEP.finditer(raw))
        bounds = [m.start() for m in seps] + [len(raw)]
        for i in range(len(seps)):
            chunk = raw[bounds[i]:bounds[i + 1]]

            if _looks_like_email(chunk):
                yield chunk
    else:
        if _looks_like_email(raw):
            yield raw


def _iter_source_files(source_dir: Path) -> Iterator[Path]:
    files = (p for p in source_dir.rglob("*") if p.is_file())
    return iter(sorted(files))


def _sample_enron_files(source_dir: Path, k: int, seed: int) -> list[Path]:
    all_files = sorted(p for p in source_dir.rglob("*") if p.is_file())
    if k <= 0 or k >= len(all_files):
        return all_files
    rng = random.Random(seed)
    return sorted(rng.sample(all_files, k))


def _is_english(text: str) -> Optional[bool]:
    t = text.strip()
    if not t:
        return None
    if not _HAVE_LANGDETECT:
        return True
    try:
        return detect(t) == TARGET_LANG
    except LangDetectException:
        return None


def _sender_key(from_header: Optional[str]) -> Optional[str]:
    if not from_header:
        return None
    addrs = [a for _, a in getaddresses([from_header]) if a]
    if not addrs:
        return None
    addr = addrs[0].lower().strip()
    if "@" not in addr:
        return None
    return f"addr:{addr}"


def _normalize_subject(subject: Optional[str]) -> tuple[str, bool]:
    if not subject:
        return "", False
    s = subject.strip()
    is_reply = False
    while True:
        m = _REPLY_PREFIX.match(s)
        if not m:
            break
        is_reply = True
        s = s[m.end():]
    return _WS.sub(" ", s.lower()).strip(), is_reply


def _thread_keys(rec: dict) -> list[str]:
    keys: list[str] = []
    for field in ("message_id", "in_reply_to", "references"):
        val = rec.get(field)
        if val:
            for mid in _MSGID.findall(val):
                keys.append(f"mid:{mid}")
    nsubj, is_reply = _normalize_subject(rec.get("subject"))
    if is_reply and nsubj:
        keys.append(f"subj:{nsubj}")
    return keys


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            lo, hi = (ra, rb) if ra < rb else (rb, ra)
            self.parent[hi] = lo


def _shingles(text: str, k: int) -> set[str]:
    words = re.findall(r"\w+", text.lower())
    if not words:
        return set()
    if len(words) < k:
        return set(words)
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def _near_clusters(records: list[dict], *, threshold: float, num_perm: int,
                   shingle_k: int, seed: int) -> list[list[str]]:
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    minhashes: dict[str, "MinHash"] = {}
    for rec in records:
        sh = _shingles(rec.get("text") or "", shingle_k)
        if not sh:
            continue
        m = MinHash(num_perm=num_perm, seed=seed)
        m.update_batch([s.encode("utf-8") for s in sh])
        minhashes[rec["id"]] = m
        lsh.insert(rec["id"], m)

    uf = _UnionFind()
    for rec in records:
        uf.find(rec["id"])
    for rid, m in minhashes.items():
        for other in lsh.query(m):
            if other != rid:
                uf.union(rid, other)

    groups: dict[str, list[str]] = {}
    for rec in records:
        groups.setdefault(uf.find(rec["id"]), []).append(rec["id"])
    return list(groups.values())


def _dominant(values: list):
    counts: dict = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1

    return max(sorted(counts), key=lambda v: counts[v])


def _assign_splits(comp_members: dict[str, list[dict]]) -> int:
    splits = ("train", "val", "test")
    fracs = {"train": 1.0 - VAL_FRAC - TEST_FRAC, "val": VAL_FRAC, "test": TEST_FRAC}

    strata: dict[tuple, list[tuple]] = {}
    mixed = 0
    for members in comp_members.values():
        canonical = min(r["id"] for r in members)
        labels = [r["label"] for r in members]
        comp_label = _dominant(labels)
        comp_source = _dominant([r["source"] for r in members])
        if len(set(labels)) > 1:
            mixed += 1

        if comp_source == "spamassassin":
            hard = _dominant([bool(r.get("_is_hard_ham")) for r in members])
        else:
            hard = False
        stratum = (comp_label, comp_source, hard)
        strata.setdefault(stratum, []).append((canonical, len(members), members))

    for comps in strata.values():
        comps.sort(key=lambda c: (-c[1], c[0]))
        total = sum(sz for _, sz, _ in comps)
        target = {s: total * fracs[s] for s in splits}
        running = {s: 0.0 for s in splits}
        n = len(comps)

        forced: dict[str, str] = {}
        if n >= 3:
            forced[comps[-1][0]] = "test"
            forced[comps[-2][0]] = "val"
        elif n == 2:
            forced[comps[-1][0]] = "test"

        ordered = ([c for c in comps if c[0] in forced]
                   + [c for c in comps if c[0] not in forced])
        for canon, sz, members in ordered:
            if canon in forced:
                split = forced[canon]
            else:
                split = max(splits, key=lambda s: target[s] - running[s])
            running[split] += sz
            for r in members:
                r["split"] = split
    return mixed


def build_dataset(
    raw_dir: Path,
    out_path: Path,
    *,
    seed: int = DEFAULT_SEED,
    enron_sample: int = DEFAULT_ENRON_SAMPLE,
    limit_per_source: int = 0,
    near_dedup: bool = True,
    near_threshold: float = NEAR_THRESHOLD,
    near_num_perm: int = NEAR_NUM_PERM,
    near_shingle_k: int = NEAR_SHINGLE_K,
    near_max_cluster: int = NEAR_MAX_CLUSTER,
) -> dict:
    stats = {
        "parsed": 0,
        "dropped_non_email": 0,
        "dropped_non_english": 0,
        "dropped_empty_or_undetected": 0,
        "dropped_duplicate": 0,
        "skipped_unknown_source": [],
        "kept": 0,
        "mixed_label_components": 0,
        "near_threshold": near_threshold,
        "near_clusters": 0,
        "near_largest": [],
        "dropped_near_thinned": 0,
        "near_clusters_leaked": 0,
        "by_source": {},
        "by_label": {},
        "by_split": {},
        "by_source_split": {},
        "by_source_label_split": {},
        "hard_ham_by_split": {},
    }
    if not _HAVE_LANGDETECT:
        print("[warn] langdetect не установлен -> фильтр языка ОТКЛЮЧЁН "
              "(pip install langdetect). Выборка может содержать не-английские письма.",
              file=sys.stderr)

    records: list[dict] = []
    seen_text_hashes: set[str] = set()

    for source_dir in sorted(p for p in raw_dir.iterdir() if p.is_dir()):
        source = source_dir.name
        label = SOURCE_LABELS.get(source)
        if label is None:
            stats["skipped_unknown_source"].append(source)
            continue

        if source == "enron":
            files: Iterable[Path] = _sample_enron_files(source_dir, enron_sample, seed)
        else:
            files = _iter_source_files(source_dir)

        n_from_source = 0
        for path in files:
            if limit_per_source and n_from_source >= limit_per_source:
                break
            for raw in iter_message_bytes(path):
                if limit_per_source and n_from_source >= limit_per_source:
                    break
                stats["parsed"] += 1
                try:
                    rec = email_to_epi(raw, source=source, label=label)
                except Exception:
                    stats["dropped_non_email"] += 1
                    continue

                text = rec.get("text") or ""
                lang_ok = _is_english(text)
                if lang_ok is None:
                    stats["dropped_empty_or_undetected"] += 1
                    continue
                if not lang_ok:
                    stats["dropped_non_english"] += 1
                    continue

                h = hashlib.sha256(text.encode("utf-8")).hexdigest()
                if h in seen_text_hashes:
                    stats["dropped_duplicate"] += 1
                    continue
                seen_text_hashes.add(h)

                rec["id"] = h

                rec["_is_hard_ham"] = (source == "spamassassin" and "hard_ham" in path.parts)
                records.append(rec)
                n_from_source += 1

    near_groups: list[list[str]] = [[rec["id"]] for rec in records]
    if near_dedup and _HAVE_DATASKETCH:
        near_groups = _near_clusters(records, threshold=near_threshold,
                                     num_perm=near_num_perm, shingle_k=near_shingle_k,
                                     seed=seed)
    elif near_dedup and not _HAVE_DATASKETCH:
        print("[warn] datasketch не установлен -> near-дедуп ОТКЛЮЧЁН "
              "(uv add datasketch). Возможна утечка near-дублей между сплитами.",
              file=sys.stderr)

    multi = [g for g in near_groups if len(g) > 1]
    stats["near_clusters"] = len(multi)
    stats["near_largest"] = sorted((len(g) for g in multi), reverse=True)[:5]

    if near_max_cluster and near_max_cluster > 0:
        drop_ids: set[str] = set()
        for g in multi:
            if len(g) > near_max_cluster:
                keep = set(sorted(g)[:near_max_cluster])
                drop_ids.update(i for i in g if i not in keep)
        if drop_ids:
            records = [r for r in records if r["id"] not in drop_ids]
            near_groups = [[i for i in g if i not in drop_ids] for g in near_groups]
            stats["dropped_near_thinned"] = len(drop_ids)

    uf = _UnionFind()
    for rec in records:
        node = "id:" + rec["id"]
        uf.find(node)
        for key in filter(None, [_sender_key(rec.get("from"))]) :
            uf.union(node, key)
        for key in _thread_keys(rec):
            uf.union(node, key)

    for g in near_groups:
        for rid in g[1:]:
            uf.union("id:" + g[0], "id:" + rid)

    comp_members: dict[str, list[dict]] = {}
    for rec in records:
        root = uf.find("id:" + rec["id"])
        comp_members.setdefault(root, []).append(rec)

    stats["mixed_label_components"] = _assign_splits(comp_members)

    id_split = {r["id"]: r["split"] for r in records}
    stats["near_clusters_leaked"] = sum(
        1 for g in near_groups
        if len({id_split[i] for i in g if i in id_split}) > 1
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    records.sort(key=lambda r: (r["split"], r["source"], r["id"]))
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            clean = {k: rec.get(k) for k in OUTPUT_FIELDS}
            f.write(json.dumps(clean, ensure_ascii=False) + "\n")

    stats["kept"] = len(records)
    for rec in records:
        s, lbl, sp = rec["source"], rec["label"], rec["split"]
        stats["by_source"][s] = stats["by_source"].get(s, 0) + 1
        stats["by_label"][lbl] = stats["by_label"].get(lbl, 0) + 1
        stats["by_split"][sp] = stats["by_split"].get(sp, 0) + 1
        k = f"{s}/{sp}"
        stats["by_source_split"][k] = stats["by_source_split"].get(k, 0) + 1
        kk = f"{s}|{lbl}|{sp}"
        stats["by_source_label_split"][kk] = stats["by_source_label_split"].get(kk, 0) + 1
        if rec.get("_is_hard_ham"):
            stats["hard_ham_by_split"][sp] = stats["hard_ham_by_split"].get(sp, 0) + 1
    return stats


def _print_stats(stats: dict, out_path: Path) -> None:
    print(f"\n=== Датасет собран: {out_path} ===")
    print(f"Прочитано писем (parsed):           {stats['parsed']}")
    print(f"Отброшено не-письма:                {stats['dropped_non_email']}")
    print(f"Отброшено не-английских:            {stats['dropped_non_english']}")
    print(f"Отброшено пустых/неопределимых:     {stats['dropped_empty_or_undetected']}")
    print(f"Отброшено дублей (SHA-256 тела):    {stats['dropped_duplicate']}")
    if stats["skipped_unknown_source"]:
        print(f"Пропущены чужие папки:              {', '.join(stats['skipped_unknown_source'])}")
    if stats["mixed_label_components"]:
        print(f"Смешанных по метке компонент:       {stats['mixed_label_components']}")
    if stats.get("dropped_near_thinned"):
        print(f"Проредено в крупных near-кластерах:  {stats['dropped_near_thinned']}")
    print(f"\nИтог записано (kept):               {stats['kept']}")

    print(f"\nNear-дедуп (MinHash+LSH, порог Jaccard {stats.get('near_threshold')}):")
    print(f"  near-кластеров (>1 письма):       {stats.get('near_clusters', 0)}")
    if stats.get("near_largest"):
        print(f"  крупнейшие кластеры (размер):     {stats['near_largest']}")
    print(f"  кампаний в >1 сплите (утечка, должно 0): {stats.get('near_clusters_leaked', 0)}")

    print("\nПо источнику:")
    for k in sorted(stats["by_source"]):
        print(f"  {k:14s} {stats['by_source'][k]}")
    print("По метке:")
    for k in sorted(stats["by_label"]):
        print(f"  {k:14s} {stats['by_label'][k]}")
    tot = stats["kept"] or 1
    print("По сплиту:")
    for k in ("train", "val", "test"):
        if k in stats["by_split"]:
            n = stats["by_split"][k]
            print(f"  {k:14s} {n}  ({100 * n / tot:.1f}%)")
    print("Источник × сплит:")
    for k in sorted(stats["by_source_split"]):
        print(f"  {k:20s} {stats['by_source_split'][k]}")

    print("\nТаблица 4.2 — (source × label × split):")
    cells = stats["by_source_label_split"]
    keys = sorted(cells)
    pairs = sorted({(k.split("|")[0], k.split("|")[1]) for k in keys})
    col_tot = {sp: 0 for sp in ("train", "val", "test")}
    print(f"  {'source':14s} {'label':12s} {'train':>7s} {'val':>7s} {'test':>7s} {'итого':>7s}")
    for src, lbl in pairs:
        row = {sp: cells.get(f"{src}|{lbl}|{sp}", 0) for sp in ("train", "val", "test")}
        rt = sum(row.values())
        for sp in col_tot:
            col_tot[sp] += row[sp]
        print(f"  {src:14s} {lbl:12s} {row['train']:7d} {row['val']:7d} "
              f"{row['test']:7d} {rt:7d}")
    grand = sum(col_tot.values())
    print(f"  {'ИТОГО':14s} {'':12s} {col_tot['train']:7d} {col_tot['val']:7d} "
          f"{col_tot['test']:7d} {grand:7d}")

    hh = stats["hard_ham_by_split"]
    print("\nhard_ham (SpamAssassin) по split:")
    hh_tot = 0
    for sp in ("train", "val", "test"):
        n = hh.get(sp, 0)
        hh_tot += n
        print(f"  {sp:14s} {n}")
    print(f"  {'итого':14s} {hh_tot}")


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Сборка обучающей выборки: data/raw/* -> data/dataset.jsonl (этап 2)."
    )
    parser.add_argument("--raw", default="data/raw", help="каталог с корпусами")
    parser.add_argument("--out", default="data/dataset.jsonl", help="выходной JSONL")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="seed (детерминизм)")
    parser.add_argument("--enron-sample", type=int, default=DEFAULT_ENRON_SAMPLE,
                        help="размер детерминированной выборки Enron (0 = весь корпус)")
    parser.add_argument("--limit-per-source", type=int, default=0,
                        help="ограничение писем на источник (для быстрой проверки; 0 = без лимита)")
    parser.add_argument("--no-near", action="store_true",
                        help="отключить near-дедупликацию (оставить только точную)")
    parser.add_argument("--near-threshold", type=float, default=NEAR_THRESHOLD,
                        help="порог Jaccard для near-кластеризации (по умолч. 0.8)")
    parser.add_argument("--near-max-cluster", type=int, default=NEAR_MAX_CLUSTER,
                        help="проредить near-кластер крупнее лимита (0 = без прореживания)")
    args = parser.parse_args(argv)

    stats = build_dataset(
        Path(args.raw), Path(args.out),
        seed=args.seed, enron_sample=args.enron_sample,
        limit_per_source=args.limit_per_source,
        near_dedup=not args.no_near,
        near_threshold=args.near_threshold,
        near_max_cluster=args.near_max_cluster,
    )
    _print_stats(stats, Path(args.out))
    return 0

if __name__ == "__main__":
    raise SystemExit(_main())
