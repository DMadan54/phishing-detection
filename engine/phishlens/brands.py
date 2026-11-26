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
    domains: frozenset[str]

    def owns(self, domain: str) -> bool:
        """True for the brand's own domains and their subdomains.

        "paypal.com.evil.test" is not PayPal's: only the right-hand end of a
        name says who owns it.
        """
        domain = domain.lower().rstrip(".")
        return any(domain == d or domain.endswith("." + d) for d in self.domains)


def _read_shared(name: str) -> Any:
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
            domains=frozenset(d for d in map(normalise_domain, entry["domains"]) if d),
        )
        for entry in _read_shared("brands.json")["brands"]
    )


@cache
def load_shorteners() -> frozenset[str]:
    return frozenset(h.lower() for h in _read_shared("shorteners.json")["hosts"])


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


def brand_owning(domain: str) -> Brand | None:
    return next((b for b in load_brands() if b.owns(domain)), None)
