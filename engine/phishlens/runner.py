"""Runs checks and makes sure one broken check can't break the report.

Checks run concurrently, because most of their time is spent waiting on DNS
or HTTP. Each has a time limit. Anything a check raises, including running
out of time, becomes a check_error finding.

Logs record check names, timings and exception types only. Exception
messages are never logged or shown, because they can quote the input, and
the input (someone's email or URL) must not end up in logs.
"""

import asyncio
import logging
import time
from collections.abc import Sequence

from phishlens.findings import Check, CheckContext, Finding, Severity

CHECK_TIMEOUT_SECONDS = 10.0

logger = logging.getLogger(__name__)


def check_error(check_name: str) -> Finding:
    return Finding(
        id=f"{check_name}.check_error",
        check=check_name,
        severity=Severity.INFO,
        title="A check couldn't run",
        explanation=(
            f"The {check_name} check failed to run, so this report is missing whatever "
            "it would have found. Treat the result with a little extra caution."
        ),
    )


async def run_check[S](
    check: Check[S],
    subject: S,
    ctx: CheckContext,
    timeout: float = CHECK_TIMEOUT_SECONDS,
) -> list[Finding]:
    started = time.perf_counter()
    try:
        async with asyncio.timeout(timeout):
            findings = await check.run(subject, ctx)
    except Exception as exc:
        logger.warning("check %s failed with %s", check.name, type(exc).__name__)
        return [check_error(check.name)]
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.debug("check %s took %.1f ms", check.name, elapsed_ms)
    return findings


async def run_checks[S](
    checks: Sequence[Check[S]],
    subject: S,
    ctx: CheckContext,
    timeout: float = CHECK_TIMEOUT_SECONDS,
) -> list[Finding]:
    """Run every check at once and return their findings in check order."""
    results = await asyncio.gather(*(run_check(c, subject, ctx, timeout) for c in checks))
    findings = [finding for result in results for finding in result]
    logger.info("ran %d checks: %s", len(checks), [f.id for f in findings])
    return findings
