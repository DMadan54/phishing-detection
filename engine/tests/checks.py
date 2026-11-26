"""Tiny checks used to test the registry, runner and API."""

import asyncio
from dataclasses import dataclass

from phishlens.findings import CheckContext, Finding, Severity
from phishlens.subjects import RawEmail, RawUrl


@dataclass(frozen=True)
class StaticCheck:
    """Always returns one INFO finding named after itself."""

    name: str

    async def run(self, subject: RawEmail | RawUrl, ctx: CheckContext) -> list[Finding]:
        return [
            Finding(
                id=f"{self.name}.seen",
                check=self.name,
                severity=Severity.INFO,
                title="Seen",
                explanation="This test check always reports itself.",
            )
        ]


@dataclass(frozen=True)
class CrashingCheck:
    """Raises with a message that quotes the input, which must never leak."""

    name: str

    async def run(self, subject: RawEmail | RawUrl, ctx: CheckContext) -> list[Finding]:
        raise ValueError(f"could not parse {subject!r}")


@dataclass(frozen=True)
class HangingCheck:
    name: str

    async def run(self, subject: RawEmail | RawUrl, ctx: CheckContext) -> list[Finding]:
        await asyncio.sleep(60)
        return []
