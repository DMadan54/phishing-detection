"""SPF, DKIM, ARC and DMARC evaluation, shared by the authentication checks.

These functions only work out results; the checks turn results into
findings. DMARC needs the SPF and DKIM results too, so it calls the same
functions. The per-request DNS cache makes the repeated lookups free.

pyspf and dkimpy are synchronous, so they run in a worker thread with a
BlockingDns that hands every lookup back to our (fakeable) resolver.

pyspf has no parameter for its DNS function: it calls a module-level
spf.DNSLookup. We replace that once, with a function that uses whichever
resolver the current task put in a context variable. asyncio.to_thread
copies context variables into the thread, so concurrent requests never see
each other's resolver.
"""

import asyncio
import contextvars
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import dkim
import spf

from phishlens.dnsbridge import BlockingDns
from phishlens.domains import aligned, domain_of_address, normalise_domain, org_domain
from phishlens.email.config import EmailConfig
from phishlens.email.parse import ParsedEmail
from phishlens.email.received import ReceivedHop, sending_hop
from phishlens.findings import CheckContext, Severity
from phishlens.services import DnsResolver, DnsTemporaryError, RecordType

# --- pyspf DNS hook ----------------------------------------------------------

_spf_dns: contextvars.ContextVar[BlockingDns] = contextvars.ContextVar("spf_dns")


def _spf_lookup(name: str, qtype: str, strict: bool = True, timeout: float = 20) -> list[Any]:
    """Drop-in for spf.DNSLookup, in the shape pyspf expects."""
    if qtype not in ("A", "AAAA", "MX", "PTR", "TXT"):
        return []  # e.g. the obsolete SPF record type
    rdtype: RecordType = qtype  # type: ignore[assignment]
    try:
        records = _spf_dns.get().resolve(name, rdtype)
    except DnsTemporaryError as exc:
        raise spf.TempError(f"DNS {exc}") from None
    key = (name, qtype)
    if qtype == "TXT":
        return [(key, [r.encode("latin-1")]) for r in records]
    if qtype == "MX":
        answers = []
        for r in records:
            preference, _, host = r.partition(" ")
            answers.append((key, (int(preference or 0), host)))
        return answers
    return [(key, r) for r in records]


spf.DNSLookup = _spf_lookup


# --- SPF ---------------------------------------------------------------------

SpfResult = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]


@dataclass(frozen=True, slots=True)
class SpfOutcome:
    result: SpfResult | None  # None when no sending hop could be found
    domain: str | None  # the envelope domain that was checked
    hop: ReceivedHop | None


def envelope_domain(msg: ParsedEmail, hop: ReceivedHop | None) -> tuple[str, str | None]:
    """The MAIL FROM address SPF checks, and its domain.

    Return-Path records the envelope sender. For the null sender (<>, used
    by bounces) SPF checks the HELO name instead (RFC 7208 section 2.3).
    """
    if msg.return_path:
        return msg.return_path, domain_of_address(msg.return_path)
    helo = hop.from_helo if hop else None
    return f"postmaster@{helo}", normalise_domain(helo) if helo else None


async def evaluate_spf(msg: ParsedEmail, ctx: CheckContext, config: EmailConfig) -> SpfOutcome:
    hop = sending_hop(msg.received, config.trusted_receivers)
    sender, domain = envelope_domain(msg, hop)
    if hop is None or hop.from_ip is None:
        return SpfOutcome(None, domain, hop)
    if domain is None:
        return SpfOutcome("none", None, hop)

    blocking = BlockingDns(ctx.dns, asyncio.get_running_loop())
    helo = hop.from_helo or domain

    def run() -> SpfResult:
        query = spf.query(i=str(hop.from_ip), s=sender, h=helo, timeout=10)
        result, _code, _explanation = query.check()
        return str(result)  # type: ignore[return-value]

    token = _spf_dns.set(blocking)
    try:
        result = await asyncio.to_thread(run)
    finally:
        _spf_dns.reset(token)
    if result not in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
        result = "permerror"
    return SpfOutcome(result, domain, hop)


# --- DKIM and ARC ------------------------------------------------------------

DkimStatus = Literal["pass", "fail", "permerror", "temperror"]


@dataclass(frozen=True, slots=True)
class DkimSignature:
    domain: str | None  # d=
    selector: str | None  # s=
    status: DkimStatus
    reason: str  # short and plain, for explanations


def _tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in value.split(";"):
        name, eq, tag_value = item.partition("=")
        if eq:
            tags[name.strip().lower()] = re.sub(r"\s+", "", tag_value)
    return tags


def _txt_for_dkimpy(blocking: BlockingDns) -> Any:
    def lookup(name: bytes | str, timeout: float = 5) -> bytes | None:
        text = name.decode("ascii", "replace") if isinstance(name, bytes) else name
        records = blocking.resolve(text.rstrip("."), "TXT")
        return records[0].encode("latin-1") if records else None

    return lookup


def _verify_signatures(
    raw: bytes, signatures: list[str], blocking: BlockingDns
) -> list[DkimSignature]:
    dnsfunc = _txt_for_dkimpy(blocking)
    results: list[DkimSignature] = []
    for index, value in enumerate(signatures):
        tags = _tags(value)
        domain = normalise_domain(tags.get("d", ""))
        selector = tags.get("s") or None
        try:
            verifier = dkim.DKIM(raw, minkey=1024)
            ok = verifier.verify(idx=index, dnsfunc=dnsfunc)
            status: DkimStatus = "pass" if ok else "fail"
            reason = "the signature is valid" if ok else "the signed content was changed"
        except DnsTemporaryError:
            status, reason = "temperror", "the signing key couldn't be looked up"
        except dkim.KeyFormatError:
            status, reason = "permerror", "the signing key is missing or unusable"
        except dkim.ValidationError:
            status, reason = "permerror", "the signature is badly formed"
        except Exception:
            status, reason = "fail", "the signature could not be verified"
        results.append(DkimSignature(domain, selector, status, reason))
    return results


async def verify_dkim(msg: ParsedEmail, ctx: CheckContext) -> list[DkimSignature]:
    signatures = [h.value for h in msg.headers_named("DKIM-Signature")]
    if not signatures:
        return []
    blocking = BlockingDns(ctx.dns, asyncio.get_running_loop())
    return await asyncio.to_thread(_verify_signatures, msg.raw, signatures, blocking)


ArcResult = Literal["pass", "fail", "none"]


async def verify_arc(msg: ParsedEmail, ctx: CheckContext) -> ArcResult:
    if not msg.headers_named("ARC-Seal"):
        return "none"
    blocking = BlockingDns(ctx.dns, asyncio.get_running_loop())

    def run() -> ArcResult:
        try:
            cv, _results, _comment = dkim.arc_verify(msg.raw, dnsfunc=_txt_for_dkimpy(blocking))
        except Exception:
            return "fail"
        return "pass" if cv == b"pass" else "fail"

    return await asyncio.to_thread(run)


async def is_mailing_list(msg: ParsedEmail, ctx: CheckContext) -> bool:
    """A List-Id header plus an ARC chain that validates.

    Mailing lists legitimately break SPF and DKIM, and ARC records what the
    authentication looked like before the list changed the message. Both
    can be added by an attacker too, so callers only lower severity one
    step, never drop a finding.
    """
    return msg.list_id is not None and await verify_arc(msg, ctx) == "pass"


def lower(severity: Severity) -> Severity:
    order = list(Severity)
    return order[max(0, order.index(severity) - 1)]


# --- DMARC -------------------------------------------------------------------

Policy = Literal["none", "quarantine", "reject"]


@dataclass(frozen=True, slots=True)
class DmarcPolicy:
    found_at: str  # the name the record was published under (without _dmarc.)
    policy: Policy  # what applies to the From domain (p= or sp=)
    adkim: Literal["r", "s"]
    aspf: Literal["r", "s"]
    pct: int
    record: str


def parse_dmarc(record: str, found_at: str, for_subdomain: bool) -> DmarcPolicy | None:
    """Read a DMARC record (RFC 7489 section 6.3). None if it isn't one."""
    tags = _tags(record)
    if tags.get("v", "").upper() != "DMARC1" or not record.strip().lower().startswith("v="):
        return None

    def policy(value: str | None) -> Policy | None:
        value = (value or "").lower()
        return value if value in ("none", "quarantine", "reject") else None  # type: ignore[return-value]

    main = policy(tags.get("p"))
    if main is None:
        # RFC 7489 6.6.3: an invalid or missing p= is treated as "none".
        main = "none"
    applied = (policy(tags.get("sp")) or main) if for_subdomain else main
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100
    adkim: Literal["r", "s"] = "s" if tags.get("adkim", "r").lower() == "s" else "r"
    aspf: Literal["r", "s"] = "s" if tags.get("aspf", "r").lower() == "s" else "r"
    return DmarcPolicy(found_at, applied, adkim, aspf, pct, record)


async def find_dmarc_policy(domain: str, dns: DnsResolver) -> DmarcPolicy | None:
    """Look for the From domain's policy, then its organisational domain's.

    Raises DnsTemporaryError if a lookup fails, so "couldn't check" is never
    mistaken for "has no policy".
    """
    organisation = org_domain(domain)
    for name in dict.fromkeys((domain, organisation)):
        records = [
            r
            for r in await dns.resolve(f"_dmarc.{name}", "TXT")
            if r.lower().startswith("v=dmarc1")
        ]
        if len(records) == 1:
            return parse_dmarc(records[0], name, for_subdomain=name != domain)
        if len(records) > 1:
            return None  # RFC 7489 6.6.3: more than one record means no policy
    return None


@dataclass(frozen=True, slots=True)
class DmarcEvaluation:
    from_domain: str
    policy: DmarcPolicy | None
    spf: SpfOutcome
    dkim: list[DkimSignature]
    spf_aligned: bool
    dkim_aligned: list[str] = field(default_factory=list)  # passing d= domains that align
    passed_elsewhere: list[str] = field(default_factory=list)  # passing domains that don't

    @property
    def passed(self) -> bool:
        return self.spf_aligned or bool(self.dkim_aligned)


async def evaluate_dmarc(
    msg: ParsedEmail, ctx: CheckContext, config: EmailConfig, from_domain: str
) -> DmarcEvaluation:
    policy = await find_dmarc_policy(from_domain, ctx.dns)
    adkim = policy.adkim if policy else "r"
    aspf = policy.aspf if policy else "r"
    mode = {"r": "relaxed", "s": "strict"}

    spf_outcome = await evaluate_spf(msg, ctx, config)
    signatures = await verify_dkim(msg, ctx)

    spf_aligned = bool(
        spf_outcome.result == "pass"
        and spf_outcome.domain
        and aligned(spf_outcome.domain, from_domain, mode[aspf])  # type: ignore[arg-type]
    )
    dkim_aligned: list[str] = []
    elsewhere: list[str] = []
    for sig in signatures:
        if sig.status != "pass" or not sig.domain:
            continue
        if aligned(sig.domain, from_domain, mode[adkim]):  # type: ignore[arg-type]
            dkim_aligned.append(sig.domain)
        else:
            elsewhere.append(sig.domain)
    if spf_outcome.result == "pass" and spf_outcome.domain and not spf_aligned:
        elsewhere.insert(0, spf_outcome.domain)

    return DmarcEvaluation(
        from_domain=from_domain,
        policy=policy,
        spf=spf_outcome,
        dkim=signatures,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        passed_elsewhere=list(dict.fromkeys(elsewhere)),
    )
