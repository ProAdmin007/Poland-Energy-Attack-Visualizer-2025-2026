"""Download the two CERT Polska source PDFs from cert.pl next to app.py.

The app works without them (page links then open the official PDFs), but
tools/verify_sources.py needs local copies.

Usage:  python tools/fetch_reports.py
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
# cert.pl answers 403 to Python's default User-Agent.
USER_AGENT = "Mozilla/5.0 (compatible; poland-attack-visualizer/1.1)"


def main() -> int:
    data = json.loads((BASE_DIR / "data" / "incidents.json").read_text(encoding="utf-8"))
    for s in data["metadata"]["sources"]:
        target = BASE_DIR / s["file"]
        if target.exists():
            print(f"exists      {target.name}")
            continue
        print(f"downloading {s['pdf_url']}")
        req = urllib.request.Request(s["pdf_url"], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
        if not body.startswith(b"%PDF-"):
            print(f"ERROR: {s['pdf_url']} did not return a PDF")
            return 1
        target.write_bytes(body)
        print(f"saved       {target.name} ({len(body):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
