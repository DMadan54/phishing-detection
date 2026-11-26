"""Settings for the email checks.

Both trust lists are empty by default, which is the safe choice for pasted
emails: we can't know which provider received them, so no Received or
Authentication-Results header is trusted beyond the topmost external hop.
"""

import os
from dataclasses import dataclass
from datetime import timedelta


def _names(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(n.strip().lower().rstrip(".") for n in value.split(",") if n.strip())


@dataclass(frozen=True, slots=True)
class EmailConfig:
    # Hosts of the recipient's own mail system, e.g. "google.com" for Gmail.
    # When set, the sending hop must be written by one of them (see
    # received.sending_hop).
    trusted_receivers: frozenset[str] = frozenset()
    # authserv-ids whose Authentication-Results headers we believe, e.g.
    # "mx.google.com". Everyone else's are treated as possibly forged.
    trusted_authserv_ids: frozenset[str] = frozenset()
    # How far the Date header may be ahead of, or behind, the time the
    # message was received before it's reported.
    future_tolerance: timedelta = timedelta(days=1)
    stale_after: timedelta = timedelta(days=7)

    @classmethod
    def from_env(cls) -> "EmailConfig":
        return cls(
            trusted_receivers=_names(os.environ.get("PHISHLENS_TRUSTED_RECEIVERS")),
            trusted_authserv_ids=_names(os.environ.get("PHISHLENS_TRUSTED_AUTHSERV_IDS")),
        )
