"""Unicode data for spotting lookalike names: skeletons and scripts.

Skeletons (Unicode Technical Standard #39, section 4). Many characters look
the same but are different: the Latin "a" and the Cyrillic one, the digit
"1" and the letter "l", "rn" and "m". confusables.txt maps each such character to one
"prototype". The skeleton of a string is: decompose it (NFD), replace every
character with its prototype, decompose again. Two strings that look alike
have the same skeleton, so "paypal", "paypa1" and paypal spelled with a
Cyrillic "a" all match.

confusables.txt maps some characters to capitals (the digit 0 becomes "O"),
so skeletons here are also lower-cased: domain names are case-insensitive.

Scripts (Scripts.txt). A label that mixes scripts, such as Latin and
Cyrillic in one word, is almost never legitimate. Following UTS #39's
"highly restrictive" profile, Latin may still be combined with Han and the
Japanese kana, with Han and Hangul, or with Han and Bopomofo, because real
Japanese, Korean and Chinese names do that. Characters in the Common and
Inherited scripts (digits, hyphens, combining marks) don't count.

Both files are pinned in shared/unicode/ (Unicode 18.0.0, hashes in
SHA256SUMS) and never downloaded at runtime.
"""

import bisect
import unicodedata
from functools import cache
from importlib import resources
from pathlib import Path

ALLOWED_SCRIPT_MIXES = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),
    frozenset({"Latin", "Han", "Hangul"}),
    frozenset({"Latin", "Han", "Bopomofo"}),
)
NEUTRAL_SCRIPTS = frozenset({"Common", "Inherited", "Unknown"})


def _read(name: str) -> str:
    repo_copy = Path(__file__).resolve().parents[3] / "shared" / "unicode" / name
    if repo_copy.is_file():
        return repo_copy.read_text(encoding="utf-8")
    return (resources.files("phishlens") / "data" / "unicode" / name).read_text(encoding="utf-8")


def _codepoints(field: str) -> str:
    return "".join(chr(int(cp, 16)) for cp in field.split())


@cache
def confusables() -> dict[str, str]:
    """Character -> prototype string, from confusables.txt."""
    table: dict[str, str] = {}
    for line in _read("confusables.txt").splitlines():
        line = line.split("#", 1)[0].strip().lstrip("﻿")
        if not line:
            continue
        source, target, *_ = (field.strip() for field in line.split(";"))
        table[_codepoints(source)] = _codepoints(target)
    return table


def skeleton(text: str) -> str:
    table = confusables()
    mapped = "".join(table.get(c, c) for c in unicodedata.normalize("NFD", text))
    return unicodedata.normalize("NFD", mapped).lower()


@cache
def _script_ranges() -> tuple[list[int], list[int], list[str]]:
    starts: list[int] = []
    ends: list[int] = []
    names: list[str] = []
    rows: list[tuple[int, int, str]] = []
    for line in _read("Scripts.txt").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        codes, script = (field.strip() for field in line.split(";"))
        low, _, high = codes.partition("..")
        rows.append((int(low, 16), int(high or low, 16), script))
    for start, end, script in sorted(rows):
        starts.append(start)
        ends.append(end)
        names.append(script)
    return starts, ends, names


def script_of(char: str) -> str:
    starts, ends, names = _script_ranges()
    code = ord(char)
    i = bisect.bisect_right(starts, code) - 1
    return names[i] if i >= 0 and code <= ends[i] else "Unknown"


def scripts_in(text: str) -> frozenset[str]:
    return frozenset(script_of(c) for c in text) - NEUTRAL_SCRIPTS


def is_mixed_script(label: str) -> bool:
    found = scripts_in(label)
    if len(found) <= 1:
        return False
    return not any(found <= allowed for allowed in ALLOWED_SCRIPT_MIXES)
