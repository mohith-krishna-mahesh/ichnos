"""Symmetric Cryptanalysis Attacks: ECB, CBC, Stream, GCM."""

from __future__ import annotations

from ichnos.crypto.symmetric.attacks.cbc import (
    cbc_bit_flip,
    cbc_padding_oracle,
    cbc_recover_key_iv_reuse,
)
from ichnos.crypto.symmetric.attacks.ecb import (
    count_duplicate_blocks,
    crack_ecb_byte_at_a_time,
    detect_ecb,
    ecb_cut_and_paste,
)
from ichnos.crypto.symmetric.attacks.gcm import gcm_forge_tag, gcm_recover_auth_key_single_block
from ichnos.crypto.symmetric.attacks.mitm import meet_in_the_middle
from ichnos.crypto.symmetric.attacks.stream import (
    break_reused_nonce,
    crib_drag_stream,
    multi_time_pad_space_crack,
)

__all__ = [
    "detect_ecb",
    "count_duplicate_blocks",
    "crack_ecb_byte_at_a_time",
    "ecb_cut_and_paste",
    "cbc_bit_flip",
    "cbc_padding_oracle",
    "cbc_recover_key_iv_reuse",
    "crib_drag_stream",
    "multi_time_pad_space_crack",
    "break_reused_nonce",
    "gcm_recover_auth_key_single_block",
    "gcm_forge_tag",
    "meet_in_the_middle",
]
