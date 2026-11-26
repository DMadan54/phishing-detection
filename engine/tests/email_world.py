"""The fake DNS the email fixtures live in, and helpers to load them.

Every domain a fixture uses has its SPF, DMARC and DKIM records here, so the
checks run exactly as they would against real DNS, with nothing leaving the
machine. Brand domains (paypal.com) get records similar to the real ones.
"""

from functools import cache
from pathlib import Path

from phishlens.email.parse import ParsedEmail, parse_email
from tests.fakes import FakeDns

FIXTURES = Path(__file__).parent / "fixtures" / "email"
DKIM_KEY = (FIXTURES / "keys" / "dkim-test-public.txt").read_text().strip()

SIGNING_DOMAINS = (
    "shop.example",
    "mail.shop.example",
    "esp.example",
    "evil.test",
    "paypa1.test",
    "lists.example",
)

SPF = {
    "company.example": "v=spf1 ip4:192.0.2.50 -all",
    "shop.example": "v=spf1 ip4:192.0.2.10 ip4:192.0.2.11 -all",
    "mail.shop.example": "v=spf1 ip4:192.0.2.10 ip4:192.0.2.12 -all",
    "em.mail.shop.example": "v=spf1 include:mail.shop.example ip4:192.0.2.11 -all",
    "evil.test": "v=spf1 ip4:203.0.113.0/24 -all",
    "paypa1.test": "v=spf1 ip4:203.0.113.20 -all",
    "paypal.com": "v=spf1 ip4:198.18.0.0/16 -all",
    "lists.example": "v=spf1 ip4:198.51.100.20 -all",
    "softfail.example": "v=spf1 ip4:198.51.100.200 ~all",
    "permerror.example": "v=spf1 ip4:not-an-address -all",
    # random.test publishes no SPF record at all.
}

DMARC = {
    "company.example": "v=DMARC1; p=quarantine; adkim=r; aspf=r",
    "shop.example": "v=DMARC1; p=reject; adkim=r; aspf=r",
    "paypal.com": "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com",
    "paypa1.test": "v=DMARC1; p=none",
    "lists.example": "v=DMARC1; p=none",
    "evil.test": "v=DMARC1; p=none",
    "softfail.example": "v=DMARC1; p=none",
    "permerror.example": "v=DMARC1; p=none",
}


def world_dns() -> FakeDns:
    dns = FakeDns()
    for domain, record in SPF.items():
        dns.add(domain, "TXT", record)
    for domain, record in DMARC.items():
        dns.add(f"_dmarc.{domain}", "TXT", record)
    for domain in SIGNING_DOMAINS:
        dns.add(f"s1._domainkey.{domain}", "TXT", DKIM_KEY)
    return dns


@cache
def raw_fixture(name: str) -> bytes:
    return (FIXTURES / f"{name}.eml").read_bytes()


def fixture(name: str) -> ParsedEmail:
    return parse_email(raw_fixture(name))


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*.eml"))
