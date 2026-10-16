"""Check every source reference in data/incidents.json against the PDFs.

For each reference, the section name (or one of its parts, split on " / " or " – ")
must appear on the cited PDF page, or on one of the two pages before it
(a section that continues onto the cited page).

Usage:  python tools/verify_sources.py
Needs:  pip install -r requirements-dev.txt
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from pypdf import PdfReader

BASE_DIR = Path(__file__).resolve().parent.parent
LOOKBACK = 2


def norm(text: str) -> str:
    # Letters/digits only: survives hyphenated line breaks and odd dashes.
    return re.sub(r"[^a-z0-9]", "", text.lower())


def iter_refs(data: dict):
    for inc in data["incidents"]:
        for r in inc["source_references"]:
            yield f"incident {inc['id']}", r
    for e in data["timeline"]:
        for r in e["source_references"]:
            yield f"event {e['id']}", r
    for p in data["attack_paths"]:
        for n in p["nodes"]:
            yield f"node {n['id']}", n["source"]


def main() -> int:
    data = json.loads((BASE_DIR / "data" / "incidents.json").read_text(encoding="utf-8"))
    pages: dict[str, list[str]] = {}
    for s in data["metadata"]["sources"]:
        pdf = BASE_DIR / s["file"]
        if not pdf.exists():
            print(f"MISSING PDF: {pdf}")
            return 2
        pages[s["id"]] = [norm(p.extract_text() or "") for p in PdfReader(pdf).pages]

    failures = 0
    for owner, ref in iter_refs(data):
        texts = pages[ref["source_id"]]
        page = ref["page"]
        if not 1 <= page <= len(texts):
            print(f"FAIL  {owner}: page {page} out of range")
            failures += 1
            continue
        parts = [norm(x) for x in re.split(r"\s+[/–]\s+", ref["section"]) if x.strip()]
        window = range(max(1, page - LOOKBACK), page + 1)
        hit = next((pg for pg in reversed(window) for part in parts if part in texts[pg - 1]), None)
        if hit is None:
            print(f"FAIL  {owner}: '{ref['section']}' not found on p.{page} (or {LOOKBACK} pages before)")
            failures += 1
        elif hit != page:
            print(f"ok    {owner}: '{ref['section']}' heading on p.{hit}, continues to p.{page}")
    total = sum(1 for _ in iter_refs(data))
    print(f"\n{total - failures}/{total} references verified")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
