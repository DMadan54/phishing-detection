# Check reference

One row per finding id. Ids are stable: the web app, the extension and the
evaluation refer to findings by id, so an id is never reused for a different
meaning. Every id is `<check name>.<what>`.

Severities here are the defaults. Findings marked "lowered on mailing lists"
drop one step when the message has a `List-Id` header and a valid ARC chain.

## Email: authentication

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `email.spf.fail` | MEDIUM (lowered on mailing lists) | The delivering server's IP isn't on the envelope domain's SPF list, which ends in `-all`. | Someone else may be sending with that domain as the envelope sender. | Forwarding and mailing lists resend from their own servers; a stale SPF record when an old email is analysed. |
| `email.spf.softfail` | LOW | The domain says the IP probably isn't allowed (`~all`) but asks not to reject. | Weaker version of a fail. | Same as `spf.fail`; many domains use `~all` while setting up. |
| `email.spf.none` | LOW | The envelope domain publishes no SPF record. | Nothing restricts who can send as that domain. | Small or personal domains that never set SPF up. |
| `email.spf.error` | LOW | SPF couldn't be evaluated: the record is broken (permerror) or DNS failed (temperror). | No SPF result either way. | Temporary DNS outages; records over the 10-lookup limit. |
| `email.spf.no_sending_ip` | INFO | No Received header records a delivery from an external IP (or none written by a trusted receiver). | SPF can't be checked; DMARC relies on DKIM alone. | Messages saved without their trace headers; `PHISHLENS_TRUSTED_RECEIVERS` set to the wrong hosts. |
| `email.dkim.missing` | LOW | No DKIM signature. | No cryptographic proof of origin or integrity. | Lots of legitimate mail (small servers, personal mail) is unsigned. |
| `email.dkim.invalid` | MEDIUM (lowered on mailing lists) | A DKIM signature is present but doesn't verify, or its key is missing or unusable. | The message may have been altered after signing. | Mailing lists that edit the subject or add footers; forwarders that rewrap lines; the signer's key rotated since the email was sent. |
| `email.dkim.other_domain` | INFO | Every valid signature is from a domain other than the From domain. | The signature proves nothing about the From address. | Normal for newsletter and transactional email services that sign with their own domain. |
| `email.dmarc.not_aligned` | HIGH, MEDIUM if `p=none` (lowered on mailing lists) | SPF or DKIM passed, but only for a domain that isn't the From domain (relaxed or strict alignment, as the policy says). | The classic spoof: authenticated as `evil.example` while claiming to be `paypal.com`. | Mailing lists and forwarders; misconfigured third-party senders. |
| `email.dmarc.fail` | HIGH, MEDIUM if `p=none` (lowered on mailing lists) | Neither SPF nor DKIM passed for any domain, and the From domain has a DMARC policy. | Nothing shows the From domain sent it. | Old emails whose keys or records changed since (set `PHISHLENS_TRUSTED_AUTHSERV_IDS` to use the provider's result recorded on delivery). |
| `email.dmarc.no_policy` | LOW | The From domain publishes no DMARC record. | Anyone can put that address in From and nothing contradicts it. | Many small domains have no DMARC. |
| `email.dmarc.pass` | INFO | SPF or DKIM passed for a domain aligned with From, or a trusted provider recorded DMARC pass on delivery. | Explains why a message is authentic. It proves origin, not honesty: a lookalike domain can pass DMARC for itself. | None. |
| `email.auth_results.untrusted` | INFO | Authentication-Results headers from authserv-ids that aren't configured as trusted. They're ignored. | Anyone can write these headers. | Normal: every forwarded or pasted email carries other servers' results. |
| `email.auth_results.contradicted` | HIGH | An untrusted Authentication-Results header claims a pass that PhishLens's own SPF, DKIM or DMARC check can't reproduce. | A planted "everything passed" header is a known filter-evasion trick. | Results recorded by an intermediate server before a change that broke them. Exempt when that server sealed them with a valid ARC chain. |
| `email.forwarding.mailing_list` | INFO | `List-Id` is present and the ARC chain validates. | Explains why some authentication findings were lowered. | An attacker can add both; that's why findings drop only one step. |
