# Threat model

What PhishLens assumes, what it defends against, and the gaps it knows
about. Updated as components are built; this version covers the email
engine.

## Assets and attackers

- **The person checking a message.** The attacker wants them to trust a
  phishing email, so the attacker controls everything in the message:
  every header, the body, the attachments.
- **The PhishLens server.** It parses hostile input, so the attacker may
  try to crash it, slow it down, or make it reach internal systems.

## Trust decisions

| Input | Trusted? | Why |
|-------|----------|-----|
| Headers below the sending hop | No | Written before the message reached anyone the recipient trusts; the sender can forge whole hops. |
| The topmost Received hop with an external IP | Yes, by default | Written by the recipient's own provider, after the message left the sender's hands. `PHISHLENS_TRUSTED_RECEIVERS` narrows this to named hosts. |
| Authentication-Results headers | No, unless the authserv-id is in `PHISHLENS_TRUSTED_AUTHSERV_IDS` | Anyone can write one. A false "pass" is reported as `email.auth_results.contradicted`. |
| ARC seals plus List-Id | Partly | They only lower severity one step, because an attacker can add both to their own message. |
| DNS answers | Yes | Needed for SPF, DKIM and DMARC. Tests replace DNS completely. |

## Defences in place

- **Request size limits** (10 MiB email, 2048-character URL), enforced while
  the body streams in, so a huge request can't exhaust memory.
- **The parser never raises**, and caps MIME parts (500) and links (1000).
  Every check is fuzzed with mangled fixtures in the tests.
- **A check that crashes or hangs** becomes a `check_error` finding after
  10 seconds; the report still comes back.
- **No user data in logs**: only check names, timings, finding ids and
  exception types. Exception messages are never logged because they can
  quote the input.
- **Nothing in an email is opened or run.** Links are parsed as text, never
  fetched. Attachments are read as bytes; oletools reads VBA without
  executing it.

## Known gaps

- **Threads can't be stopped.** pyspf, dkimpy and oletools are synchronous
  and run in worker threads. When the 10-second check timeout fires, the
  report moves on, but a thread stuck on a hostile file keeps running until
  the library gives up. Planned fix: move attachment parsing into the
  sandboxed worker container, where a process can be killed.
- **Parser bugs in the libraries.** A crafted Office file could exploit a
  bug in oletools or olefile. The same move to the worker would contain it.
- **ARC sealers aren't vetted.** Any valid ARC chain counts. Planned fix: a
  list of trusted list operators.
- **Time of analysis.** SPF and DKIM are checked when the email is analysed,
  not when it arrived. Old legitimate mail can fail because keys rotated or
  records changed. Configuring the user's provider as a trusted authserv-id
  lets its delivery-time DMARC result be used instead.
- **Ambiguous headers.** Different software can read the same header
  differently (an unquoted address in a display name, duplicate From
  headers). PhishLens reports these as `email.from.invalid` rather than
  guessing which reading a mail client will show.
