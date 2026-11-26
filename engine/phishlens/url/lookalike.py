"""Does a domain imitate a brand's?

The registered name (the label before the suffix, "paypa1" in paypa1.com)
is compared with every brand label in shared/brands.json. In order:

1. homograph: it contains non-ASCII letters and has the same Unicode
   skeleton as the brand (paypal spelled with a Cyrillic "a"). This is the
   strongest signal: nobody registers that by accident.
2. character_swap: plain ASCII with the same skeleton (paypa1, rnicrosoft,
   g00gle): digits and letter pairs that look like other letters.
3. tld_swap: the brand's exact name under another TLD (paypal.co).
4. typo: one edit away (two for names of 9+ letters), counting a swap of
   neighbouring letters as one edit (Damerau-Levenshtein). Keys next to each
   other on a keyboard are named, because that's how real typos look.
5. combo: the brand plus a hyphen or a sign-in word (paypal-secure-login,
   securepaypal).

Never flagged: the brand's own domains and their subdomains, and domains
in the "known popular" set (the Tranco top 10k, if downloaded), which are
established sites rather than fresh lookalikes. Short brand labels (under
5 letters) skip the typo rule, which would match too many ordinary names.

The same rules run in the browser extension; shared/test-vectors/
lookalike.json keeps the two in agreement.
"""

import difflib
import logging
import os
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Literal, Protocol

import idna

from phishlens.brands import Brand, load_brands
from phishlens.domains import normalise_domain, split_domain
from phishlens.findings import CharacterDifference, LookalikeEvidence
from phishlens.url.unicode_data import scripts_in, skeleton

logger = logging.getLogger(__name__)

Rule = Literal["homograph", "character_swap", "tld_swap", "typo", "combo"]
RULE_ORDER: tuple[Rule, ...] = ("homograph", "character_swap", "tld_swap", "typo", "combo")
TYPO_MIN_LENGTH = 5
COMBO_SUBSTRING_MIN_LENGTH = 6
PHISHY_WORDS = frozenset(
    [
        "secure",
        "security",
        "login",
        "signin",
        "sign",
        "verify",
        "verification",
        "account",
        "accounts",
        "support",
        "help",
        "update",
        "billing",
        "service",
        "services",
        "online",
        "auth",
        "wallet",
        "confirm",
        "customer",
        "alert",
        "unlock",
        "recovery",
        "team",
        "official",
    ]
)

_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")


@cache
def _neighbours() -> dict[str, frozenset[str]]:
    """Keys next to each key on a QWERTY keyboard, including diagonals."""
    where = {key: (r, c) for r, row in enumerate(_ROWS) for c, key in enumerate(row)}
    return {
        key: frozenset(
            other
            for other, (r2, c2) in where.items()
            if other != key and abs(r - r2) <= 1 and abs(c - c2) <= 1
        )
        for key, (r, c) in where.items()
    }


def keyboard_adjacent(a: str, b: str) -> bool:
    return b in _neighbours().get(a, frozenset())


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment variant).

    The number of single-letter insertions, deletions, substitutions and
    swaps of two neighbouring letters needed to turn a into b.
    """
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(a)][len(b)]


@dataclass(frozen=True, slots=True)
class LookalikeMatch:
    rule: Rule
    brand: Brand
    domain: str  # the registrable domain that was checked, ASCII
    domain_unicode: str  # the same, as a person sees it
    genuine: str  # the brand domain being imitated
    reason: str  # plain English, completes "it ...": 'uses "1" in place of "l"'
    differences: tuple[CharacterDifference, ...] = ()

    def evidence(self) -> LookalikeEvidence:
        return LookalikeEvidence(
            seen=self.domain_unicode,
            seen_ascii=self.domain,
            genuine=self.genuine,
            differences=self.differences,
        )


class LookalikeDetector(Protocol):
    def check(self, domain: str) -> LookalikeMatch | None: ...


class NoLookalikes:
    """A detector that never matches, for callers that want none."""

    def check(self, domain: str) -> LookalikeMatch | None:
        return None


def _to_unicode(ascii_name: str) -> str:
    try:
        return idna.decode(ascii_name)
    except (idna.IDNAError, UnicodeError):
        return ascii_name


def _char_name(text: str) -> str:
    if len(text) != 1:
        return f'"{text}"'
    try:
        return unicodedata.name(text)
    except ValueError:
        return f"U+{ord(text):04X}"


def differences(seen: str, genuine: str) -> tuple[CharacterDifference, ...]:
    """Where seen differs from genuine, for highlighting side by side."""
    found = []
    matcher = difflib.SequenceMatcher(a=seen, b=genuine, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        a, b = seen[i1:i2], genuine[j1:j2]
        if tag == "replace":
            description = f"{_char_name(a)} instead of {_char_name(b)}"
        elif tag == "insert":
            description = f"missing {_char_name(b)}"
        else:
            description = f"extra {_char_name(a)}"
        found.append(CharacterDifference(position=i1, seen=a, genuine=b, description=description))
    return tuple(found)


def _typo_reason(seen: str, genuine: str) -> str:
    if len(seen) == len(genuine):
        i = next(k for k in range(len(seen)) if seen[k] != genuine[k])
        if i + 1 < len(seen) and seen[i] == genuine[i + 1] and seen[i + 1] == genuine[i]:
            return f'swaps the letters "{genuine[i]}" and "{genuine[i + 1]}"'
        if keyboard_adjacent(seen[i], genuine[i]):
            return f'has "{seen[i]}" instead of "{genuine[i]}", the key next to it'
        return f'has "{seen[i]}" instead of "{genuine[i]}"'
    if len(seen) == len(genuine) + 1:
        return "adds an extra letter"
    if len(seen) == len(genuine) - 1:
        return "leaves out a letter"
    return "differs by two letters"


def _swap_reason(seen: str, genuine: str) -> str:
    changes = [d for d in differences(seen, genuine) if d.seen and d.genuine]
    if not changes:
        return "is written to look the same"
    d = changes[0]
    if all(c.isascii() for c in d.seen):
        return f'uses "{d.seen}" in place of "{d.genuine}"'
    if len(d.seen) > 1:
        alphabets = " and ".join(sorted(scripts_in(d.seen) - {"Latin"})) or "another"
        return f"spells it with look-alike {alphabets} letters"
    return f'uses the look-alike character {_char_name(d.seen)} in place of "{d.genuine}"'


@dataclass(frozen=True)
class BrandLookalikes:
    brands: Sequence[Brand] = field(default_factory=load_brands)
    popular: frozenset[str] = frozenset()

    def check(self, domain: str) -> LookalikeMatch | None:
        ascii_name = normalise_domain(domain)
        if ascii_name is None:
            return None
        parts = split_domain(ascii_name)
        if not parts.label or not parts.suffix:
            return None
        if parts.registrable in self.popular or any(b.owns(ascii_name) for b in self.brands):
            return None

        label_unicode = _to_unicode(parts.label)
        seen_unicode = _to_unicode(parts.registrable)
        best: LookalikeMatch | None = None
        for brand in self.brands:
            for genuine_label in brand.labels:
                match = self._compare(
                    brand, genuine_label, parts.label, parts.suffix, label_unicode
                )
                if match is None:
                    continue
                rule, reason = match
                genuine = self._genuine_domain(brand, genuine_label)
                candidate = LookalikeMatch(
                    rule=rule,
                    brand=brand,
                    domain=parts.registrable,
                    domain_unicode=seen_unicode,
                    genuine=genuine,
                    reason=reason,
                    differences=differences(seen_unicode, genuine),
                )
                if best is None or RULE_ORDER.index(rule) < RULE_ORDER.index(best.rule):
                    best = candidate
        return best

    @staticmethod
    def _compare(
        brand: Brand, genuine: str, label: str, suffix: str, label_unicode: str
    ) -> tuple[Rule, str] | None:
        if label_unicode != genuine and skeleton(label_unicode) == skeleton(genuine):
            reason = _swap_reason(label_unicode, genuine)
            return ("homograph" if not label_unicode.isascii() else "character_swap"), reason
        if label == genuine:
            usual = split_domain(BrandLookalikes._genuine_domain(brand, genuine)).suffix
            return "tld_swap", f"uses .{suffix} instead of .{usual}"
        if len(genuine) >= TYPO_MIN_LENGTH:
            limit = 2 if len(genuine) >= 9 else 1
            if edit_distance(label, genuine) <= limit:
                return "typo", _typo_reason(label, genuine)
        tokens = [t for t in label.split("-") if t]
        if genuine in tokens and len(tokens) > 1:
            extra = "-".join(t for t in tokens if t != genuine)
            return "combo", f'adds "{extra}" to the name'
        if len(genuine) >= COMBO_SUBSTRING_MIN_LENGTH and genuine in label and label != genuine:
            rest = label.replace(genuine, " ").replace("-", " ").split()
            if rest and all(word in PHISHY_WORDS for word in rest):
                return "combo", f'adds "{" ".join(rest)}" to the name'
        return None

    @staticmethod
    def _genuine_domain(brand: Brand, genuine_label: str) -> str:
        """The brand domain with this name: the .com if there is one, else
        the first in the brand's list."""
        own = [d for d in brand.domains if split_domain(d).label == genuine_label]
        if f"{genuine_label}.com" in own:
            return f"{genuine_label}.com"
        return own[0] if own else f"{genuine_label}.com"


# --- the "known popular" set -------------------------------------------------

POPULAR_FILE = Path(__file__).resolve().parents[3] / "shared" / "data" / "tranco-top10k.txt"


@cache
def load_popular(path: Path = POPULAR_FILE) -> frozenset[str]:
    """Registrable domains from the Tranco list, if scripts/fetch_tranco.py was run."""
    if not path.is_file():
        logger.info("no popular-domain list at %s; run scripts/fetch_tranco.py", path.name)
        return frozenset()
    lines = path.read_text(encoding="utf-8").split()
    return frozenset(line.strip().lower() for line in lines if line.strip())


@cache
def default_detector() -> BrandLookalikes:
    """The detector the checks use. PHISHLENS_POPULAR_DOMAINS overrides where
    the popular list is read from; set it empty to use no list (the tests do,
    so results don't depend on whether the optional file was downloaded)."""
    configured = os.environ.get("PHISHLENS_POPULAR_DOMAINS")
    if configured is None:
        return BrandLookalikes(popular=load_popular())
    return BrandLookalikes(popular=load_popular(Path(configured)) if configured else frozenset())
