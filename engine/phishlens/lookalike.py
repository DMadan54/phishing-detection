"""Hook for lookalike-domain detection.

The real detector (homoglyphs, typos, brand names in other domains) is built
in the URL and domain milestone and plugged in here. Until then the email
sender check is given NoLookalikes, which never matches, and its tests use a
fake detector.
"""

from dataclasses import dataclass
from typing import Protocol

from phishlens.brands import Brand


@dataclass(frozen=True, slots=True)
class LookalikeMatch:
    brand: Brand
    domain: str
    reason: str  # plain English, e.g. 'uses "1" in place of "l" in paypal.com'


class LookalikeDetector(Protocol):
    def check(self, domain: str) -> LookalikeMatch | None: ...


class NoLookalikes:
    def check(self, domain: str) -> LookalikeMatch | None:
        return None
