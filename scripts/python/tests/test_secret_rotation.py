"""Unit tests for pam_secret_rotation value generation."""

import pytest

from pam_secret_rotation import generate_secret


def test_generate_secret_default_length():
    assert len(generate_secret()) == 32


def test_generate_secret_custom_length():
    assert len(generate_secret(40)) == 40


def test_generate_secret_complexity():
    value = generate_secret(20)
    assert any(c.islower() for c in value)
    assert any(c.isupper() for c in value)
    assert any(c.isdigit() for c in value)


def test_generate_secret_rejects_short_length():
    with pytest.raises(ValueError):
        generate_secret(8)


def test_generate_secret_is_random():
    assert generate_secret() != generate_secret()
