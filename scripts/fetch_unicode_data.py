"""Download the pinned Unicode data files used for lookalike detection.

    uv run python scripts/fetch_unicode_data.py           # verify, or fetch if missing
    uv run python scripts/fetch_unicode_data.py --update  # fetch and record new hashes

The files are committed under shared/unicode/ so the engine and the extension
never download anything at runtime. SHA256SUMS pins their exact contents:
without --update, a download that doesn't match is refused.

- confusables.txt (Unicode Technical Standard #39): which characters look
  alike, used to compute "skeletons": paypal, and paypal spelled with a
  Cyrillic "a", have the same one.
- Scripts.txt (Unicode Character Database): which script each character
  belongs to, used to spot labels that mix scripts.
- license.txt: the Unicode License v3 these files are distributed under.
"""

import hashlib
import sys
from pathlib import Path

import httpx

VERSION = "18.0.0"
FILES = {
    "confusables.txt": f"https://www.unicode.org/Public/{VERSION}/security/confusables.txt",
    "Scripts.txt": f"https://www.unicode.org/Public/{VERSION}/ucd/Scripts.txt",
    "license.txt": "https://www.unicode.org/license.txt",
}
OUT = Path(__file__).resolve().parents[1] / "shared" / "unicode"
SUMS = OUT / "SHA256SUMS"


def recorded() -> dict[str, str]:
    if not SUMS.exists():
        return {}
    pairs = (line.split() for line in SUMS.read_text().splitlines() if line.strip())
    return {name: digest for digest, name in pairs}


def main(update: bool) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    expected = recorded()
    digests: dict[str, str] = {}
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for name, url in FILES.items():
            path = OUT / name
            if path.exists() and not update:
                data = path.read_bytes()
            else:
                response = client.get(url)
                response.raise_for_status()
                data = response.content
            digest = hashlib.sha256(data).hexdigest()
            if not update and name in expected and expected[name] != digest:
                print(f"{name}: hash mismatch (expected {expected[name]}, got {digest})")
                return 1
            path.write_bytes(data)
            digests[name] = digest
            print(f"{name}: {len(data)} bytes, sha256 {digest}")
    SUMS.write_text("".join(f"{digests[n]}  {n}\n" for n in sorted(digests)), newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(update="--update" in sys.argv))
