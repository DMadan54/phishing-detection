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

## Email: content

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `email.links.text_mismatch` | HIGH | An HTML link's visible text is a URL or domain owned by someone other than the link's real destination. | You read a trusted address and land somewhere else. | Marketing click-tracking: legitimate services routinely show `www.brand.com` while linking through their tracking domain. |
| `email.links.ip_host` | MEDIUM | A link's host is an IP address, including the decimal, hex and octal spellings browsers accept (`http://3325256781/`). | No domain name to recognise or hold anyone to account; disguised spellings hide that it's an IP at all. | Internal tools and device admin pages linked by IP in workplace mail. |
| `email.links.shortener` | LOW | A link goes through a host in `shared/shorteners.json`. | The real destination is hidden. | Very common in social media and marketing mail. |
| `email.links.dangerous_scheme` | HIGH | A `javascript:`, `data:`, `vbscript:` or `file:` link (tabs and newlines inside the scheme are ignored, as browsers do). | Runs script or opens embedded content instead of a website. | Practically none in email. |
| `email.attachments.executable` | HIGH | The file name ends in a program or script extension, or the bytes are an executable (MZ, ELF or Mach-O header). Trailing dots and spaces are ignored, as Windows does. | Runs code when opened. | Software vendors and IT departments sending installers; developers sharing scripts. |
| `email.attachments.double_extension` | CRITICAL | A document or image extension followed by a program extension (`invoice.pdf.exe`). | Windows hides the last extension, so only the fake one shows. | Almost none. |
| `email.attachments.bidi_name` | CRITICAL | The file name contains a text-direction control character (for example U+202E RIGHT-TO-LEFT OVERRIDE). | `invoice<RLO>fdp.exe` displays as `invoiceexe.pdf`. | Almost none; right-to-left languages don't need control characters in file names. |
| `email.attachments.archive` | LOW, MEDIUM if password-protected | A zip, rar, 7z, iso, img or similar container. | Carries files past scanners; a password stops scanning entirely. | Archives are common in ordinary mail; password-protected zips are common for sending confidential files. |
| `email.attachments.macros` | HIGH | An Office file in which oletools finds VBA macros. | Macros run code when the reader clicks "Enable content". | Internal business spreadsheets that legitimately use macros. |
| `email.attachments.html` | MEDIUM, HIGH with smuggling markers | An HTML or SVG attachment. HIGH when it contains `atob(`, `new Blob(`, `createObjectURL`, `.download`, `<form` or similar. | Opens in the browser, where it can show a fake login page or build and download a file (HTML smuggling). | Some newsletters, receipts and booking confirmations attached as HTML. |
| `email.attachments.type_mismatch` | MEDIUM, HIGH if it's really a program | The bytes don't match the file's extension or declared type (`report.pdf` that is a zip). Generic `application/octet-stream` declarations are ignored. | A disguised file is trying to get past a person or a filter. | Mislabelled files from badly written software; unusual formats the sniffer doesn't know. |
| `email.language.urgency` | LOW | Phrases such as "account has been suspended", "within 24 hours", "payment failed", "urgent". | Pressure stops people thinking. Supporting evidence only. | Genuine reminders, deadlines and security notices. |
| `email.language.credential_request` | LOW | Phrases such as "verify your account", "confirm your password", "enter your card details". | Phishing asks for exactly these. Supporting evidence only. | Genuine account-security mail and sign-up confirmations. |

## URL: lexical

These read only the URL text, parsed with the WHATWG URL Standard (the rules browsers use), so `https://evil.example\@paypal.com` is read as going to `evil.example`, as a browser would.

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `url.parse.invalid` | MEDIUM | The text can't be parsed as a URL by the browser rules. | Broken URLs confuse filters while still working in some programs. | Typos and truncated links pasted by people. |
| `url.scheme.dangerous` | HIGH | `javascript:`, `data:`, `vbscript:` or `file:`. | Runs script or opens embedded content instead of a website. | Practically none in links sent to people. |
| `url.host.ip_literal` | MEDIUM | The host is an IP address, in any spelling browsers accept (`2130706433`, `0x7f.1`, `[::1]`). | No domain name to recognise or hold anyone to account. | Device admin pages and internal tools. |
| `url.host.percent_encoded` | MEDIUM | The host is written with %-codes (`%70aypal.com`). | Unreadable to people and naive filters; browsers decode it. | Almost none. |
| `url.host.deep_subdomains` | LOW | More than 4 labels in front of the registrable domain. | Pushes the real domain out of view. | CDNs and some cloud services use deep names. |
| `url.host.long` | LOW | Host longer than 60 characters. | Hides the part that matters. | Cloud storage and CDN hostnames. |
| `url.host.high_entropy` | LOW | The registrable label is 12+ characters with 3.5+ bits per character of Shannon entropy. | Looks machine-generated (domain-generation algorithms). | Hash-like names of some legitimate services. |
| `url.host.shortener` | LOW | A host from `shared/shorteners.json`. | Hides the destination. | Very common legitimately. Replaces `email.links.shortener`. |
| `url.userinfo.present` | HIGH if the part before `@` looks like a site or names a brand, otherwise MEDIUM | The URL has `user@` or `user:pass@` before the host. | People read `paypal.com@evil.example` as PayPal; the browser goes to `evil.example`. | Rare in links sent to people; some FTP and internal links. |
| `url.brand.in_subdomain` | HIGH | A brand keyword appears in the subdomain of a domain the brand doesn't own (`login.microsoft.com.evil.example`). | Only the end of a name says who owns it; the start is free for anyone to write. | Partners and resellers with brand names in their subdomains. |
| `url.brand.in_path` | MEDIUM with a sign-in word in the path, otherwise LOW | A brand keyword appears in the path on someone else's domain. | Fake sign-in pages are often at `/paypal/login`. | News, reviews and support forums that mention brands. |
| `url.tld.suspicious` | LOW | The TLD is in `shared/suspicious-tlds.json` (sources and date in the file). | These TLDs are heavily over-represented in phishing. | Most sites on them are legitimate. |
| `url.port.non_standard` | LOW | An explicit port other than 80 or 443. | Often a temporary or hand-run server. | Development servers and some self-hosted services. |

## URL: lookalikes and international names

The same rules judge sender domains (`email.from.lookalike`) and link domains. Domains that belong to the brand, and domains in the popular set (the Tranco top 10k from `scripts/fetch_tranco.py`, if downloaded), are never flagged. `shared/test-vectors/lookalike.json` lists the expected result for every rule, including the legitimate cases.

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `url.lookalike.homograph` | CRITICAL | A non-ASCII name with the same Unicode TR39 skeleton as a brand label (`paypal` spelled with a Cyrillic `a`). Evidence shows both domains and names each different character. | Looks identical to the reader; nobody registers it by accident. | Practically none. |
| `url.lookalike.character_swap` | HIGH | An ASCII name with the same skeleton as a brand: digits or letter pairs that look like letters (`paypa1`, `rnicrosoft`, `g00gle`). | Easy to misread at a glance. | Rare; legitimate names that happen to share a skeleton with a brand. |
| `url.lookalike.tld_swap` | HIGH | The brand's exact name under another TLD (`paypal.co`). | Looks right except for the ending most people don't check. | Country domains a brand really owns but `brands.json` doesn't list; the popular set covers most. |
| `url.lookalike.typo` | HIGH | One edit from a brand label (two for 9+ letters), counting a swap of neighbouring letters as one; keyboard-neighbour mistakes are named. | Catches people who mistype, and readers who don't notice. | Real words or names one letter from a brand (`chose` and `chase`); brands under 5 letters are skipped for this reason. |
| `url.lookalike.combo` | MEDIUM | The brand name plus a hyphenated word or a sign-in word (`paypal-secure-login`, `securepaypal`). | Looks like an official service page. | Fan sites, resellers and support businesses that use brand names. |
| `url.idn.mixed_script` | HIGH | One label mixes scripts (Latin with Cyrillic or Greek, for example). Latin with Han, kana, Hangul or Bopomofo is allowed, as UTS #39 allows. | Real names almost never mix alphabets within a word. | Some brand-plus-word names in other languages. |
| `url.idn.punycode` | INFO | The name is internationalised; shows both the stored `xn--` form and the displayed form. | Lets the reader see exactly what the name is. | None (informational). |

## URL: redirect chain

Only `/analyse/url` follows redirects (pass `"follow_redirects": false` to skip it). Links inside emails are never fetched, because fetching a phishing link can tell the attacker the message was read. Every hop goes through the SSRF guard in `phishlens/net/safe_fetch.py`: only http and https, every resolved address must be public, the connection is pinned to the checked IP, at most 10 hops, 20 seconds and 64 KB per page. Pages are read as text only; nothing is executed.

| Finding id | Severity | What it means | Why it matters | Known false positives |
|------------|----------|---------------|----------------|-----------------------|
| `url.redirect.chain` | INFO | The link redirects at least once; every hop is listed as evidence. | Shows where the link really goes. | None (informational). |
| `url.redirect.shortener` | LOW | A shortener appears after the first hop. | Chained shorteners hide the destination from filters. | Marketing links that wrap shorteners in tracking. |
| `url.redirect.to_lookalike` | HIGH | A hop on a different owner's domain is a brand lookalike. | The innocent-looking first address leads to a fake site. | Inherits the lookalike rules' false positives. |
| `url.redirect.meta_refresh` | MEDIUM | A page redirects with `<meta http-equiv="refresh">`. | Gets past scanners that only follow HTTP redirects. | Old sites and some "you are leaving" pages. |
| `url.redirect.script` | MEDIUM | A page redirects with a literal `location = "..."` or `location.replace(...)`. | Same as meta refresh; found by reading the text, never by running it. | Single-page apps and consent pages. |
| `url.redirect.blocked` | MEDIUM | A hop pointed at a non-public address (private, loopback, link-local, metadata and so on) and was refused. | Public links have no reason to point inside a network; may be an SSRF attempt. | Links to intranet sites in internal mail. |
| `url.redirect.too_many` | MEDIUM | More than 10 hops, or a loop. | Long chains wear scanners down. | Broken site configurations. |
| `url.redirect.error` | INFO | The chain couldn't be followed to the end (DNS failure, timeout, connection or TLS error, a non-web link). | The other checks still apply to the address itself. | Sites that are simply down. |
