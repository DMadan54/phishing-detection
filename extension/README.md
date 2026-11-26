# extension

The browser extension that warns before you type a password on a lookalike
page. TypeScript, Manifest V3, for Chrome and Firefox. Built in the
"Extension" milestone.

Privacy rules it follows:

- Cheap checks run locally, inside the extension.
- Only a page that looks like a login form on an unfamiliar domain is sent
  for a deeper check, and only its URL: never page content, form values or
  cookies.
- Nothing is sent until the user has opted in.

Its local checks run the same test vectors as the engine's matching checks
(`shared/test-vectors/`), so the two can't drift apart.
