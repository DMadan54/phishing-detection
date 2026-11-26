"""Download the "known popular" domain set: the top of the Tranco list.

    uv run python scripts/fetch_tranco.py           # the pinned list
    uv run python scripts/fetch_tranco.py --latest  # move the pin to today's list

Tranco (https://tranco-list.eu) ranks sites by combining several traffic
sources, and each daily list has a permanent ID. Lookalike detection skips
domains on it: google.de isn't in brands.json, but it's an established site,
not a fresh lookalike of google.com.

The domains go to shared/data/tranco-top10k.txt, which is git-ignored (it's
third-party data and changes daily). The list ID is pinned in
shared/tranco-list.json, so everyone gets the same list. Without the file
the engine still works; it just can't rule out popular sites.
"""

import csv
import io
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "shared" / "tranco-list.json"
OUT = ROOT / "shared" / "data" / "tranco-top10k.txt"
SIZE = 10_000
API = "https://tranco-list.eu/api/lists"


def main(latest: bool) -> int:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        if latest or not PIN.exists():
            meta = client.get(f"{API}/date/latest").raise_for_status().json()
            pin = {
                "list_id": meta["list_id"],
                "created_on": meta["created_on"],
                "size": SIZE,
                "source": "https://tranco-list.eu",
            }
            PIN.write_text(json.dumps(pin, indent=2) + "\n", newline="\n")
        pin = json.loads(PIN.read_text())
        url = f"https://tranco-list.eu/download/{pin['list_id']}/{pin['size']}"
        rows = client.get(url).raise_for_status().text

    domains = [row[1].strip().lower() for row in csv.reader(io.StringIO(rows)) if len(row) >= 2]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(dict.fromkeys(domains)) + "\n", newline="\n")
    print(f"wrote {len(domains)} domains from Tranco list {pin['list_id']} to {OUT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(latest="--latest" in sys.argv))
