"""Small helpers for building evidence that points into an email."""

from phishlens.email.parse import HeaderField, ParsedEmail
from phishlens.findings import HeaderEvidence

MAX_VALUE = 300  # long header values are cut so a report stays readable


def from_field(field: HeaderField) -> HeaderEvidence:
    value = field.value if len(field.value) <= MAX_VALUE else field.value[:MAX_VALUE] + "..."
    return HeaderEvidence(name=field.name, value=value, span=field.span)


def header(msg: ParsedEmail, name: str, index: int = 0) -> list[HeaderEvidence]:
    """Evidence for the index-th header with this name, or nothing."""
    fields = msg.headers_named(name)
    return [from_field(fields[index])] if index < len(fields) else []
