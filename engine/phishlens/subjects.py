"""What gets analysed: the raw input exactly as the user supplied it.

Checks receive these unparsed. Parsing belongs to the checks (and to shared
parsing helpers added later), because a message that fails to parse is
itself evidence.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawEmail:
    """An RFC 5322 message as bytes.

    Kept as bytes, not text: DKIM signatures cover the exact bytes, so any
    decoding or line-ending change could break a valid signature.
    """

    raw: bytes


@dataclass(frozen=True, slots=True)
class RawUrl:
    """A URL string as typed or pasted, not yet parsed or normalised."""

    url: str
