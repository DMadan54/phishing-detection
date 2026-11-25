# PhishLens

PhishLens is an explainable phishing detector: give it a raw email or a URL
and it tells you in plain English *why* something looks like phishing,
pointing at the exact header, link or page element that gave it away. A
companion browser extension warns you before you type a password on a
lookalike login page.

## What it checks

- **Sender authentication**: whether SPF, DKIM and DMARC show that the
  email really came from the domain it claims.
- **Sender identity**: display names that impersonate a brand, lookalike
  and homoglyph domains, mismatched `Reply-To` and `Return-Path` addresses.
- **Links**: link text that doesn't match its destination, URL shorteners
  and redirect chains, newly registered domains, IP-address hosts and
  internationalised (punycode) domains.
- **Attachments**: risky file types, double extensions and macro-enabled
  documents.
- **Sandboxed pages**: suspicious pages are loaded only in an isolated
  worker, which checks for credential forms and brand impersonation.

Every result is a list of findings, each with a stable id, a plain-English
explanation and the evidence behind it. The verdict (`safe`, `suspicious` or
`phishing`) is calculated from those findings with documented weights, so
nothing is decided by a black box.

## Stack

| Part        | Built with                                                    |
|-------------|---------------------------------------------------------------|
| Engine      | Python 3.12, FastAPI, managed with uv                         |
| Worker      | Playwright in its own sandboxed container                     |
| Web app     | React, TypeScript and Vite                                    |
| Extension   | TypeScript, Manifest V3, for Chrome and Firefox               |
| Evaluation  | Python scripts and a frozen test set                          |

## Roadmap

- [ ] Scaffold
- [ ] Email checks
- [ ] URL and domain checks
- [ ] Sandboxed pages
- [ ] Scoring
- [ ] Web app
- [ ] Extension
- [ ] Evaluation
- [ ] Deploy

## Contributing

The repository ships a `commit-msg` hook in `.githooks/` that rejects commit
messages containing AI attribution (`Co-Authored-By` trailers, "Generated
with" lines, session links). Git doesn't enable hooks from a clone
automatically, so run this once after cloning:

```sh
git config core.hooksPath .githooks
```

If the hook rejects a commit, fix the message rather than bypassing it with
`--no-verify`. The match is a simple text search, so an ordinary phrase such
as "generated with pytest" is rejected too; reword it.
