"""Refresh the snapshot of IANA's RDAP bootstrap file.

    uv run python scripts/fetch_rdap_bootstrap.py

RDAP (the Registration Data Access Protocol, RFC 9082/9083) is the JSON
successor to WHOIS. Each TLD's registry runs its own RDAP server; IANA
publishes which server answers for which TLD in this file (RFC 9224). The
engine ships a snapshot, so finding the right server never needs a request.
The file changes rarely; refresh it now and then and commit the result.
"""

import json
from pathlib import Path

import httpx

URL = "https://data.iana.org/rdap/dns.json"
OUT = Path(__file__).resolve().parents[1] / "engine" / "phishlens" / "data" / "iana-rdap-dns.json"


def main() -> None:
    data = httpx.get(URL, timeout=30).raise_for_status().json()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", newline="\n")
    print(f"wrote {len(data['services'])} RDAP services (published {data['publication']})")


if __name__ == "__main__":
    main()
