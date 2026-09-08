"""ECDSA nonce reuse private key recovery.

When two ECDSA signatures share the same ephemeral nonce *k*, the private key
*d* can be recovered algebraically without any brute-force search.

Given signatures (r, s1) on message hash z1 and (r, s2) on message hash z2:

    k = (z1 - z2) * mod_inverse(s1 - s2, n)  mod n
    d = mod_inverse(r, n) * (s1 * k - z1)    mod n
"""

from __future__ import annotations

from ichnos.crypto.numtheory import mod_inverse


def recover_private_key_reused_nonce(
    r: int,
    s1: int,
    s2: int,
    z1: int,
    z2: int,
    n: int,
) -> tuple[int, int]:
    """Recover the ECDSA private key when the same nonce *k* was reused.

    Parameters
    ----------
    r : int
        The shared *r* component of both signatures (same because k is reused).
    s1 : int
        The *s* component of the first signature.
    s2 : int
        The *s* component of the second signature.
    z1 : int
        The message hash (truncated to curve order bit-length) of the first message.
    z2 : int
        The message hash of the second message.
    n : int
        The order of the elliptic-curve base point.

    Returns
    -------
    tuple[int, int]
        ``(d, k)`` where *d* is the recovered private key and *k* is the
        recovered nonce.

    Raises
    ------
    ValueError
        If ``s1 == s2 (mod n)`` — the signatures are identical and recovery
        is impossible.
    """
    ds = (s1 - s2) % n
    if ds == 0:
        raise ValueError(
            "s1 == s2 (mod n): signatures are identical, nonce recovery impossible"
        )

    # Recover the nonce k
    k = ((z1 - z2) * mod_inverse(ds, n)) % n

    # Recover the private key d
    d = (mod_inverse(r, n) * ((s1 * k) - z1)) % n

    return d, k


def recover_nonce_from_private_key(
    r: int,
    s: int,
    z: int,
    d: int,
    n: int,
) -> int:
    """Recover the ECDSA nonce *k* given the private key.

    From the ECDSA signing equation ``s = k^{-1}(z + r*d) mod n`` we get:

        k = mod_inverse(s, n) * (z + r * d)  mod n

    Parameters
    ----------
    r : int
        The *r* component of the signature.
    s : int
        The *s* component of the signature.
    z : int
        The message hash (truncated to curve order bit-length).
    d : int
        The private key.
    n : int
        The order of the elliptic-curve base point.

    Returns
    -------
    int
        The recovered nonce *k*.
    """
    k = (mod_inverse(s, n) * ((z + r * d) % n)) % n
    return k
