import pytest

from ichnos.crypto.numtheory import (
    continued_fraction,
    convergents,
    crt,
    euler_totient,
    extended_gcd,
    gcd,
    is_prime,
    mod_inverse,
    prime_factorization,
)


def test_gcd():
    assert gcd(48, 18) == 6
    assert gcd(101, 103) == 1


def test_extended_gcd():
    g, x, y = extended_gcd(48, 18)
    assert g == 6
    assert 48 * x + 18 * y == 6


def test_mod_inverse():
    assert mod_inverse(3, 26) == 9


def test_mod_inverse_no_inverse():
    with pytest.raises(ValueError):
        mod_inverse(2, 26)


def test_crt():
    assert crt([2, 3, 2], [3, 5, 7]) == 23


@pytest.mark.parametrize(
    "n, expected",
    [
        (2, True),
        (3, True),
        (17, True),
        (97, True),
        (4, False),
        (15, False),
        (100, False),
        (1, False),
        (0, False),
    ],
)
def test_is_prime(n, expected):
    assert is_prime(n) == expected


def test_prime_factorization():
    assert prime_factorization(84) == [2, 2, 3, 7]
    assert prime_factorization(97) == [97]


def test_euler_totient():
    assert euler_totient(10) == 4  # 1, 3, 7, 9
    assert euler_totient(97) == 96


def test_continued_fraction():
    assert continued_fraction(649, 200) == [3, 4, 12, 4]


def test_convergents():
    cf = [3, 4, 12, 4]
    convs = convergents(cf)
    assert convs == [(3, 1), (13, 4), (159, 49), (649, 200)]
