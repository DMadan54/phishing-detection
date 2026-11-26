"""Domain helpers: normalising hosts and working out who owns a domain.

The "registrable domain" (DMARC calls it the organisational domain) is the
part of a name someone actually registered: mail.paypal.com and paypal.com
both belong to paypal.com, but a.co.uk and b.co.uk belong to different
people, and login.microsoft.com.evil.example belongs to evil.example. The
Public Suffix List says where the registrable part starts.

tldextract ships a snapshot of that list. It's configured here to never
download a fresh copy and never write a cache, so results only change when
the pinned tldextract version is upgraded. Private suffixes such as
github.io are included, so alice.github.io and mallory.github.io count as
different owners.

The list's own algorithm has a default rule: a TLD that isn't on the list
counts as a one-label suffix. tldextract leaves such names without a
registrable domain, so that rule is applied here. It matters for real new
TLDs as well as the reserved .example and .test names the tests use.
"""

import ipaddress
from dataclasses import dataclass
from functools import cache
from typing import Literal

import idna
import tldextract

AlignmentMode = Literal["relaxed", "strict"]


@dataclass(frozen=True, slots=True)
class DomainParts:
    subdomain: str  # "login.microsoft.com" (may be empty)
    label: str  # the registered name without its suffix: "evil"
    suffix: str  # "example", "co.uk"
    registrable: str  # "evil.example"; equal to the input for a bare suffix


@cache
def _extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(
        suffix_list_urls=(),  # never download
        cache_dir=None,  # never write a cache
        include_psl_private_domains=True,
    )


def normalise_domain(name: str) -> str | None:
    """Lower-case ASCII (punycode) form of a domain, or None if it isn't one.

    Internationalised names are converted with UTS #46 processing, the same
    mapping browsers apply, so "PayPal.com." and "paypal.com" compare equal.
    """
    name = name.strip().rstrip(".")
    if not name or any(c.isspace() for c in name):
        return None
    try:
        return idna.encode(name, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None


@cache
def split_domain(domain: str) -> DomainParts:
    """Split a normalised domain into subdomain, label and suffix."""
    domain = domain.lower().rstrip(".")
    if as_ip(domain):
        return DomainParts("", domain, "", domain)
    result = _extractor()(domain)
    if result.suffix and result.domain:
        return DomainParts(
            result.subdomain, result.domain, result.suffix, f"{result.domain}.{result.suffix}"
        )
    labels = domain.split(".")
    if result.suffix:  # the whole name is a public suffix, such as "co.uk"
        return DomainParts("", "", result.suffix, domain)
    if len(labels) < 2:
        return DomainParts("", domain, "", domain)
    # The list's default rule: an unknown TLD is a one-label suffix.
    return DomainParts(".".join(labels[:-2]), labels[-2], labels[-1], ".".join(labels[-2:]))


def org_domain(domain: str) -> str:
    """The registrable domain: "mail.paypal.com" -> "paypal.com"."""
    return split_domain(domain).registrable


def aligned(a: str, b: str, mode: AlignmentMode = "relaxed") -> bool:
    """DMARC alignment: strict needs the same name, relaxed the same owner."""
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    if mode == "strict":
        return a == b
    return org_domain(a) == org_domain(b)


def same_owner(a: str, b: str) -> bool:
    return aligned(a, b, "relaxed")


def domain_of_address(address: str) -> str | None:
    """The normalised domain of an email address, or None."""
    _, at, domain = address.rpartition("@")
    return normalise_domain(domain) if at else None


def as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address a host names directly, or None for a domain name.

    Accepts the bracketed IPv6 form from URLs ("[2001:db8::1]").
    """
    host = host.strip().removeprefix("[").removesuffix("]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None
