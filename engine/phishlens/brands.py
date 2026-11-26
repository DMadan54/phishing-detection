"""The brand and URL-shortener lists from shared/.

In the repository the files are read straight from shared/. A built wheel
carries copies in phishlens/data/ (see engine/pyproject.toml).
"""

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from phishlens.domains import normalise_domain


@dataclass(frozen=True, slots=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    labels: tuple[str, ...]  # registered names lookalike detection compares against
    domains: tuple[str, ...]  # in the brand's own order, main domain first

    def owns(self, domain: str) -> bool:
        """True for the brand's own domains and their subdomains.

        "paypal.com.evil.test" is not PayPal's: only the right-hand end of a
        name says who owns it.
        """
        domain = domain.lower().rstrip(".")
        return any(domain == d or domain.endswith("." + d) for d in self.domains)


def read_shared(name: str) -> Any:
    """Load a JSON file from shared/ (or the copy packaged in a wheel)."""
    repo_copy = Path(__file__).resolve().parents[2] / "shared" / name
    if repo_copy.is_file():
        return json.loads(repo_copy.read_text(encoding="utf-8"))
    packaged = resources.files("phishlens") / "data" / name
    return json.loads(packaged.read_text(encoding="utf-8"))


@cache
def load_brands() -> tuple[Brand, ...]:
    return tuple(
        Brand(
            name=entry["name"],
            keywords=tuple(k.lower() for k in entry["keywords"]),
            labels=tuple(label.lower() for label in entry.get("labels", [])),
            domains=tuple(dict.fromkeys(d for d in map(normalise_domain, entry["domains"]) if d)),
        )
        for entry in read_shared("brands.json")["brands"]
    )


@cache
def load_shorteners() -> frozenset[str]:
    return frozenset(h.lower() for h in read_shared("shorteners.json")["hosts"])


@cache
def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    # Whole words only: "apple" matches "Apple Support" but not "pineapple".
    return re.compile(r"(?<![\w])" + re.escape(keyword) + r"(?![\w])", re.IGNORECASE)


def brands_named_in(text: str) -> list[tuple[Brand, re.Match[str]]]:
    """Every brand whose keyword appears in the text, with where it matched."""
    found: list[tuple[Brand, re.Match[str]]] = []
    for brand in load_brands():
        for keyword in brand.keywords:
            match = _keyword_pattern(keyword).search(text)
            if match:
                found.append((brand, match))
                break
    return found


def brands_in_token_text(text: str) -> list[Brand]:
    """Brands named in a hostname or path, where words run together.

    "login-paypal" and "paypal.com.secure" both name PayPal. Keywords with
    spaces are compared with the spaces removed ("royal mail" -> "royalmail").
    """
    tokens = set(re.split(r"[^a-z0-9]+", text.lower()))
    joined = re.sub(r"[^a-z0-9]+", "", text.lower())
    found = []
    for brand in load_brands():
        for keyword in brand.keywords:
            compact = re.sub(r"[^a-z0-9]+", "", keyword)
            # Short keywords must be a whole token ("ups" not "backups");
            # long ones may be joined to other words ("paypalsecure").
            if compact in tokens or (len(compact) >= 6 and compact in joined):
                found.append(brand)
                break
    return found


def brand_owning(domain: str) -> Brand | None:
    return next((b for b in load_brands() if b.owns(domain)), None)
