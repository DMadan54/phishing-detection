import pytest

from phishlens.registry import Registry, UnknownCheckError, default_registry, parse_disabled
from tests.checks import StaticCheck


def make_registry() -> Registry:
    return Registry(
        email_checks=(StaticCheck("email.one"), StaticCheck("email.two")),
        url_checks=(StaticCheck("url.one"),),
    )


def test_without_removes_named_checks() -> None:
    registry = make_registry().without({"email.one", "url.one"})
    assert [c.name for c in registry.email_checks] == ["email.two"]
    assert registry.url_checks == ()


def test_without_keeps_order() -> None:
    registry = make_registry().without(set())
    assert [c.name for c in registry.email_checks] == ["email.one", "email.two"]


def test_unknown_name_is_an_error() -> None:
    with pytest.raises(UnknownCheckError, match=r"email\.dmrac"):
        make_registry().without({"email.dmrac"})


def test_duplicate_names_are_rejected() -> None:
    with pytest.raises(ValueError, match=r"email\.one"):
        Registry(email_checks=(StaticCheck("email.one"),), url_checks=(StaticCheck("email.one"),))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, frozenset()),
        ("", frozenset()),
        ("email.one", frozenset({"email.one"})),
        (" email.one , url.one ,, ", frozenset({"email.one", "url.one"})),
    ],
)
def test_parse_disabled(value: str | None, expected: frozenset[str]) -> None:
    assert parse_disabled(value) == expected


def test_default_registry_lists_the_email_checks() -> None:
    names = default_registry().names
    assert {"email.spf", "email.dkim", "email.dmarc", "email.auth_results"} <= names
