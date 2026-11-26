"""Clients for outside information about a domain or URL: registration age
(RDAP), certificate history (crt.sh) and reputation services.

All of them talk only to fixed, well-known API hosts, never to the URL being
analysed, and all of them answer "unknown" rather than "clean" on any
failure.
"""
