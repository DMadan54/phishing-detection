import json

import pydantic
import pytest

from phishlens.findings import (
    BodyEvidence,
    Finding,
    HeaderEvidence,
    PageEvidence,
    Severity,
    Span,
    UrlEvidence,
)


def make_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "id": "email.dmarc.fail",
        "check": "email.dmarc",
        "severity": Severity.HIGH,
        "title": "Sender failed DMARC",
        "explanation": "The email says it's from paypal.com, but PayPal's servers didn't send it.",
        "evidence": (
            HeaderEvidence(
                name="From", value="PayPal <service@paypal.com>", span=Span(start=6, end=33)
            ),
            UrlEvidence(component="host", value="paypa1.example", span=Span(start=8, end=22)),
            PageEvidence(selector="form#login input[type=password]"),
            BodyEvidence(excerpt="Verify your account", span=Span(start=120, end=139)),
        ),
    }
    fields.update(overrides)
    return Finding.model_validate(fields)


def test_round_trips_through_json() -> None:
    finding = make_finding()
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding


def test_json_shape_is_plain() -> None:
    data = json.loads(make_finding().model_dump_json())
    assert data["severity"] == "high"
    assert [e["kind"] for e in data["evidence"]] == ["header", "url", "page", "body"]
    assert data["evidence"][0]["span"] == {"start": 6, "end": 33}


def test_kind_picks_the_evidence_class() -> None:
    restored = Finding.model_validate_json(make_finding().model_dump_json())
    assert [type(e) for e in restored.evidence] == [
        HeaderEvidence,
        UrlEvidence,
        PageEvidence,
        BodyEvidence,
    ]


def test_evidence_defaults_to_empty() -> None:
    finding = make_finding(evidence=())
    assert Finding.model_validate_json(finding.model_dump_json()).evidence == ()


@pytest.mark.parametrize("bad_id", ["dmarc", "Email.DMARC", "email..fail", "email.dmarc fail", ""])
def test_rejects_badly_formed_ids(bad_id: str) -> None:
    with pytest.raises(pydantic.ValidationError):
        make_finding(id=bad_id)


def test_rejects_unknown_evidence_kind() -> None:
    data = json.loads(make_finding().model_dump_json())
    data["evidence"][0]["kind"] = "cookie"
    with pytest.raises(pydantic.ValidationError):
        Finding.model_validate(data)


def test_rejects_unknown_fields() -> None:
    data = json.loads(make_finding().model_dump_json())
    data["verdict"] = "phishing"
    with pytest.raises(pydantic.ValidationError):
        Finding.model_validate(data)


@pytest.mark.parametrize(("start", "end"), [(-1, 3), (5, 4)])
def test_rejects_invalid_spans(start: int, end: int) -> None:
    with pytest.raises(pydantic.ValidationError):
        Span(start=start, end=end)


def test_empty_span_is_allowed() -> None:
    assert Span(start=3, end=3).end == 3


def test_findings_cannot_be_changed() -> None:
    finding = make_finding()
    with pytest.raises(pydantic.ValidationError):
        finding.severity = Severity.LOW  # type: ignore[misc]
