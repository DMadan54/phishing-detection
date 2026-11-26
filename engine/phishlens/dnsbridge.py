"""DNS helpers shared by the checks.

CachingDns: one per request. SPF, DKIM and DMARC each look up some of the
same records (DMARC re-evaluates SPF and DKIM itself, so the checks stay
independent). The cache makes the repeats free, and concurrent lookups of
the same record share one query.

BlockingDns: pyspf and dkimpy are synchronous libraries, so they run in a
worker thread. They still need DNS, and our resolver is async. BlockingDns
hands each lookup back to the event loop and waits for the answer, so the
synchronous code uses exactly the same (fakeable) resolver as everything
else.
"""

import asyncio
import concurrent.futures

from phishlens.services import DnsResolver, DnsTemporaryError, RecordType

DnsKey = tuple[str, RecordType]


class CachingDns:
    def __init__(self, inner: DnsResolver) -> None:
        self._inner = inner
        self._lookups: dict[DnsKey, asyncio.Task[list[str]]] = {}

    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        key = (name.lower().rstrip("."), rdtype)
        task = self._lookups.get(key)
        if task is None:
            task = asyncio.ensure_future(self._inner.resolve(*key))
            self._lookups[key] = task
        # A failed lookup stays failed for the rest of the request, so every
        # check sees the same answer.
        return list(await asyncio.shield(task))


class BlockingDns:
    """A synchronous view of an async resolver, for use in worker threads."""

    def __init__(
        self, resolver: DnsResolver, loop: asyncio.AbstractEventLoop, timeout: float = 5.0
    ) -> None:
        self._resolver = resolver
        self._loop = loop
        self._timeout = timeout

    def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        if _running_loop() is self._loop:
            raise RuntimeError("BlockingDns must not be used on the event loop thread")
        future = asyncio.run_coroutine_threadsafe(self._resolver.resolve(name, rdtype), self._loop)
        try:
            return future.result(timeout=self._timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise DnsTemporaryError("lookup timed out") from None


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None
