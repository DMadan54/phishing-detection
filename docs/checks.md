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

## Email: sender identity and headers

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `email.from.invalid` | MEDIUM | No From header, more than one, more than one address, no valid domain, or a header that reads as two addresses at different organisations (an unquoted address in the display name). | Different programs pick different senders from such headers, so filters and people can see different ones. | Badly written scripts and some automated systems. |
| `email.from.display_name_address` | HIGH | The display name contains an email address owned by someone other than the real sender. | Many mail apps show only the name, so the reader sees an address that isn't the sender. | Forwarding services that write "alice@x via service"; same-organisation addresses are already excluded. |
| `email.from.display_name_brand` | MEDIUM | The display name names a brand from `shared/brands.json`, but the address isn't on that brand's domains. | Borrowing a brand's name is the cheapest impersonation there is. | Resellers and partners ("Amazon Seller Services" from a merchant), businesses whose names contain a brand word ("Apple Valley Farm"). |
| `email.from.lookalike` | HIGH | The From domain imitates a brand's domain (from the lookalike detector). | A lookalike domain can pass SPF, DKIM and DMARC for itself. | Depends on the detector (URL and domain milestone); until then this only fires in tests. |
| `email.headers.reply_to_mismatch` | MEDIUM (lowered on mailing lists) | Reply-To is at a different organisation than From. | Replies reach the scammer even when From is spoofed or borrowed; typical of invoice and CEO fraud. | Mailing lists, newsletters whose replies go to a support platform, contact forms. |
| `email.headers.return_path_mismatch` | INFO | The bounce address is at a different organisation than From. | Context for DMARC; little on its own. | Very common with email service providers. |
| `email.headers.message_id_missing` | LOW | No Message-ID header. | Ordinary mail software always adds one; scripts often don't. | Some old or minimal mail servers. |
| `email.headers.message_id_unrelated` | LOW | The Message-ID domain matches neither From, the bounce domain nor any DKIM signer. | Suggests a bulk-sending tool rather than the claimed sender's system. | Senders whose IDs come from a provider's internal hostname (for example Outlook's `prod.outlook.com`) without a matching DKIM signature. |
| `email.date.future` | MEDIUM | The Date header is more than a day after the message arrived (or after now, when no Received time is known). | Real mail takes its date from the clock; a future date means a tool made one up. | Senders with a badly set clock. |
| `email.date.stale` | LOW | The Date header is more than a week before the message arrived. | Old messages re-sent in bulk, or a made-up date. | Messages held in a queue or retried for days; resent drafts. |
| `email.date.invalid` | LOW | The Date header is missing or isn't a valid date. | Ordinary mail software always writes a valid date. | Some broken automated senders. |
