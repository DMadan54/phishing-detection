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

## Running locally

The engine needs [uv](https://docs.astral.sh/uv/), which also installs the
right Python (3.12, pinned in `.python-version`) on first use.

```sh
# Install uv (Windows; on macOS or Linux see the uv docs)
winget install --id astral-sh.uv -e

# Create .venv with the engine and the dev tools, exactly as locked
uv sync

# Checks (CI runs the same four)
uv run ruff check
uv run ruff format --check
uv run mypy engine
uv run pytest

# Start the API on http://127.0.0.1:8000 (interactive docs at /docs)
uv run uvicorn --factory phishlens.api:create_app --reload
```

To use API keys or turn checks off, copy `.env.example` to `.env`, fill it
in, and start the API with `uv run --env-file .env uvicorn ...` instead.

Try it from another terminal:

```sh
curl http://127.0.0.1:8000/health

# An email goes in as the raw body, for example a saved .eml file
curl -X POST -H "Content-Type: message/rfc822" \
     --data-binary @message.eml http://127.0.0.1:8000/analyse/email

curl -X POST -H "Content-Type: application/json" \
     -d '{"url": "https://example.com/login"}' http://127.0.0.1:8000/analyse/url

# Only read the URL, without following its redirects (nothing is fetched)
curl -X POST -H "Content-Type: application/json" \
     -d '{"url": "https://paypal.com@login.paypa1.com/", "follow_redirects": false}' \
     http://127.0.0.1:8000/analyse/url
```

Following redirects fetches the URL through the SSRF-guarded fetcher (it
refuses every internal address), which still contacts the site. Links inside
emails are never fetched.

Limits: emails up to 10 MiB and URLs up to 2048 characters (larger gets
`413`); a malformed request gets `422`, and an email sent with the wrong
`Content-Type` gets `415`. Live tests that use the real network are marked
`live` and skipped unless you run `uv run pytest -m live`.

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
