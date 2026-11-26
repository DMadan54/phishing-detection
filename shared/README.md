# shared

Data used by both the engine and the extension, as JSON:

- the brand list (names, official domains, what each brand's lookalikes
  tend to look like)
- `test-vectors/`: inputs and expected finding ids for the checks that run
  in both places. The engine's tests and the extension's tests both run
  them, so a check that passes in one and fails in the other is caught.

Filled in from the "URL and domain" milestone onwards.
