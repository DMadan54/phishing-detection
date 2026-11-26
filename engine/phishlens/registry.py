"""The one place every check is listed.

Adding a check means adding it to default_registry(). Turning one off means
naming it in PHISHLENS_DISABLED_CHECKS (comma-separated), for example
"email.dkim,url.shortener".
"""

from collections.abc import Iterable
from dataclasses import dataclass

from phishlens.email.attachments import AttachmentCheck
from phishlens.email.auth_dkim import DkimCheck
from phishlens.email.auth_dmarc import DmarcCheck
from phishlens.email.auth_results import AuthResultsCheck
from phishlens.email.auth_spf import SpfCheck
from phishlens.email.config import EmailConfig
from phishlens.email.dates import DateCheck
from phishlens.email.forwarding import ForwardingCheck
from phishlens.email.from_check import FromCheck
from phishlens.email.headers import HeaderConsistencyCheck
from phishlens.email.language import LanguageCheck
from phishlens.email.links import LinkCheck
from phishlens.email.parse import ParsedEmail
from phishlens.findings import Check
from phishlens.lookalike import NoLookalikes
from phishlens.subjects import RawUrl


class UnknownCheckError(ValueError):
    """A check name was given that no registered check has."""


@dataclass(frozen=True, slots=True)
class Registry:
    email_checks: tuple[Check[ParsedEmail], ...] = ()
    url_checks: tuple[Check[RawUrl], ...] = ()

    def __post_init__(self) -> None:
        names = self._all_names()
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate check names: {', '.join(duplicates)}")

    def _all_names(self) -> list[str]:
        return [c.name for c in self.email_checks] + [c.name for c in self.url_checks]

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._all_names())

    def without(self, disabled: Iterable[str]) -> "Registry":
        """A copy with the named checks removed.

        An unknown name is an error, so a typo can't leave a check running
        that someone meant to turn off.
        """
        off = frozenset(disabled)
        unknown = off - self.names
        if unknown:
            raise UnknownCheckError(f"no such check: {', '.join(sorted(unknown))}")
        return Registry(
            email_checks=tuple(c for c in self.email_checks if c.name not in off),
            url_checks=tuple(c for c in self.url_checks if c.name not in off),
        )


def parse_disabled(value: str | None) -> frozenset[str]:
    """Read a comma-separated list of check names, ignoring blanks."""
    if not value:
        return frozenset()
    return frozenset(name.strip() for name in value.split(",") if name.strip())


def default_registry(email_config: EmailConfig | None = None) -> Registry:
    """Every check PhishLens runs, in the order findings are reported."""
    config = email_config or EmailConfig.from_env()
    return Registry(
        email_checks=(
            SpfCheck(config),
            DkimCheck(),
            DmarcCheck(config),
            AuthResultsCheck(config),
            ForwardingCheck(),
            FromCheck(NoLookalikes()),  # the real detector arrives with the URL checks
            HeaderConsistencyCheck(),
            DateCheck(config),
            LinkCheck(),
            AttachmentCheck(),
            LanguageCheck(),
        ),
        url_checks=(),
    )
