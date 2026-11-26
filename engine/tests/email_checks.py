"""Run email checks over fixtures inside the fake DNS world."""

from collections.abc import Sequence

from phishlens.dnsbridge import CachingDns
from phishlens.email.parse import ParsedEmail
from phishlens.findings import Check, Finding
from phishlens.runner import run_checks
from tests.email_world import fixture, world_dns
from tests.fakes import FakeDns, make_context


async def findings_for(
    name_or_msg: str | ParsedEmail,
    checks: Sequence[Check[ParsedEmail]],
    dns: FakeDns | None = None,
) -> list[Finding]:
    msg = fixture(name_or_msg) if isinstance(name_or_msg, str) else name_or_msg
    ctx = make_context(dns=dns or world_dns())
    ctx = type(ctx)(dns=CachingDns(ctx.dns), rdap=ctx.rdap, http=ctx.http, clock=ctx.clock)
    return await run_checks(checks, msg, ctx)


async def ids_for(
    name_or_msg: str | ParsedEmail,
    checks: Sequence[Check[ParsedEmail]],
    dns: FakeDns | None = None,
) -> set[str]:
    return {f.id for f in await findings_for(name_or_msg, checks, dns)}
