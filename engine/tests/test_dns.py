import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from phishlens.dnsbridge import BlockingDns, CachingDns
from phishlens.services import DnspythonResolver, DnsTemporaryError, RecordType, rdata_to_text
from tests.fakes import FakeDns


def rdata(rdtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text)


# --- rdata_to_text -----------------------------------------------------------


@pytest.mark.parametrize(
    ("rdtype", "text", "expected"),
    [
        (
            "TXT",
            '"v=spf1 " "include:_spf.example.com -all"',
            "v=spf1 include:_spf.example.com -all",
        ),
        ("A", "192.0.2.1", "192.0.2.1"),
        ("AAAA", "2001:db8::1", "2001:db8::1"),
        ("MX", "10 mx.example.com.", "10 mx.example.com"),
        ("PTR", "mail.example.com.", "mail.example.com"),
    ],
)
def test_rdata_to_text(rdtype: str, text: str, expected: str) -> None:
    assert rdata_to_text(rdata(rdtype, text)) == expected


def test_txt_keeps_every_byte() -> None:
    assert rdata_to_text(rdata("TXT", '"caf\\233"')) == "caf\xe9"


# --- DnspythonResolver error mapping (no real queries) -----------------------


class RaisingResolver(dns.asyncresolver.Resolver):
    def __init__(self, exc_type: type[Exception]) -> None:
        super().__init__(configure=False)
        self.exc_type = exc_type

    async def resolve(self, *args: object, **kwargs: object) -> dns.resolver.Answer:
        raise self.exc_type()


@pytest.mark.parametrize(
    "exc_type", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.SyntaxError]
)
async def test_missing_records_are_empty(exc_type: type[Exception]) -> None:
    resolver = DnspythonResolver(RaisingResolver(exc_type))
    assert await resolver.resolve("x.example", "TXT") == []


@pytest.mark.parametrize("exc_type", [dns.exception.Timeout, dns.resolver.NoNameservers])
async def test_failed_lookups_are_temporary_errors(exc_type: type[Exception]) -> None:
    with pytest.raises(DnsTemporaryError):
        await DnspythonResolver(RaisingResolver(exc_type)).resolve("x.example", "TXT")


# --- CachingDns --------------------------------------------------------------


async def test_cache_queries_each_record_once() -> None:
    inner = FakeDns().add("example.com", "TXT", "v=spf1 -all")
    cache = CachingDns(inner)
    results = await asyncio.gather(*(cache.resolve("Example.COM.", "TXT") for _ in range(5)))
    assert results == [["v=spf1 -all"]] * 5
    assert inner.lookups == [("example.com", "TXT")]


async def test_cache_keeps_record_types_apart() -> None:
    inner = FakeDns().add("example.com", "A", "192.0.2.1")
    cache = CachingDns(inner)
    assert await cache.resolve("example.com", "TXT") == []
    assert await cache.resolve("example.com", "A") == ["192.0.2.1"]


async def test_cache_repeats_failures() -> None:
    inner = FakeDns(failing={("example.com", "TXT")})
    cache = CachingDns(inner)
    for _ in range(2):
        with pytest.raises(DnsTemporaryError):
            await cache.resolve("example.com", "TXT")
    assert len(inner.lookups) == 1


async def test_callers_cannot_change_cached_answers() -> None:
    cache = CachingDns(FakeDns().add("example.com", "A", "192.0.2.1"))
    (await cache.resolve("example.com", "A")).append("203.0.113.9")
    assert await cache.resolve("example.com", "A") == ["192.0.2.1"]


# --- BlockingDns -------------------------------------------------------------


async def test_blocking_dns_works_from_a_thread() -> None:
    blocking = BlockingDns(
        FakeDns().add("example.com", "A", "192.0.2.1"), asyncio.get_running_loop()
    )
    assert await asyncio.to_thread(blocking.resolve, "example.com", "A") == ["192.0.2.1"]


async def test_blocking_dns_passes_errors_through() -> None:
    blocking = BlockingDns(FakeDns(failing={("example.com", "A")}), asyncio.get_running_loop())
    with pytest.raises(DnsTemporaryError):
        await asyncio.to_thread(blocking.resolve, "example.com", "A")


class SlowDns:
    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        await asyncio.sleep(10)
        return []


async def test_blocking_dns_times_out() -> None:
    blocking = BlockingDns(SlowDns(), asyncio.get_running_loop(), timeout=0.05)
    with pytest.raises(DnsTemporaryError):
        await asyncio.to_thread(blocking.resolve, "example.com", "A")


async def test_blocking_dns_refuses_the_loop_thread() -> None:
    blocking = BlockingDns(FakeDns(), asyncio.get_running_loop())
    with pytest.raises(RuntimeError):
        blocking.resolve("example.com", "A")
