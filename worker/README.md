# worker

The sandboxed page fetcher. This is the **only** component that ever loads a
suspicious page. Built in the "Sandboxed pages" milestone.

It will run Playwright in its own container with:

- no credentials and a throwaway browser profile for every page
- a hard timeout, and downloads disabled
- the same SSRF protection as the engine: only http/https, no private,
  loopback, link-local or cloud-metadata addresses, the resolved IP
  rechecked after every redirect, and caps on redirects, size and time

Nothing outside this folder may open a live phishing URL in a browser or run
its JavaScript.
