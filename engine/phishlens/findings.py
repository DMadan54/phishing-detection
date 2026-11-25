"""The core model: what a check returns and what a check is.

A check looks at one email or URL and returns zero or more Findings. Each
Finding says what is wrong in plain English and points at the exact evidence,
so the verdict can always be explained. The verdict itself is calculated
from the findings elsewhere; nothing here decides "phishing" on its own.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from phishlens.services import Clock, DnsResolver, RdapClient

# Dotted lower-case names such as "email.dmarc" (a check) or
# "email.dmarc.fail" (a finding). At least two parts.
DOTTED_NAME = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _Frozen(BaseModel):
    """Base for all models: immutable, and unknown fields are an error."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Span(_Frozen):
    """Character offsets into the original input, half-open like a slice.

    ``raw[span.start:span.end]`` is the highlighted text.
    """

    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def _end_not_before_start(self) -> Self:
        if self.end < self.start:
            raise ValueError("span end must not be before start")
        return self


class HeaderEvidence(_Frozen):
    """An email header, for example From or Authentication-Results."""

    kind: Literal["header"] = "header"
    name: str = Field(min_length=1)
    value: str
    span: Span | None = None


UrlComponent = Literal["scheme", "userinfo", "host", "port", "path", "query", "fragment"]


class UrlEvidence(_Frozen):
    """One component of a URL, for example the host."""

    kind: Literal["url"] = "url"
    component: UrlComponent
    value: str
    span: Span | None = None


class PageEvidence(_Frozen):
    """An element of a page loaded in the sandbox, found by CSS selector."""

    kind: Literal["page"] = "page"
    selector: str = Field(min_length=1)
    value: str | None = None


class BodyEvidence(_Frozen):
    """A piece of an email body."""

    kind: Literal["body"] = "body"
    excerpt: str
    span: Span | None = None


# The "kind" field tells pydantic which class to build when reading JSON.
Evidence = Annotated[
    HeaderEvidence | UrlEvidence | PageEvidence | BodyEvidence,
    Field(discriminator="kind"),
]


class Finding(_Frozen):
    """One thing a check noticed, explained for a non-expert."""

    id: str = Field(pattern=DOTTED_NAME)
    check: str = Field(pattern=DOTTED_NAME)
    severity: Severity
    title: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Every outside service a check may use, so tests can fake them all."""

    dns: DnsResolver
    rdap: RdapClient
    http: httpx.AsyncClient
    clock: Clock


class Check[S](Protocol):
    """A named unit that inspects one subject (an email or a URL).

    ``run`` should return findings rather than raise. The runner still
    catches anything it raises and reports it as a check_error finding.
    """

    @property
    def name(self) -> str:
        """Dotted name, for example "email.dmarc". Used to turn it off."""
        ...

    async def run(self, subject: S, ctx: CheckContext) -> list[Finding]: ...
