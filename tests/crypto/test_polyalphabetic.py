from ichnos.crypto.classical.polyalphabetic import (
    alberti_decrypt,
    alberti_encrypt,
    autokey_decrypt,
    autokey_encrypt,
    ave_maria_decrypt,
    ave_maria_encrypt,
    bazeries_decrypt,
    bazeries_encrypt,
    beaufort_decrypt,
    beaufort_encrypt,
    bellaso_decrypt,
    bellaso_encrypt,
    chaocipher_decrypt,
    chaocipher_encrypt,
    crack_beaufort,
    gronsfeld_decrypt,
    gronsfeld_encrypt,
    jefferson_wheel_decrypt,
    jefferson_wheel_encrypt,
    keyword_shift_decrypt,
    keyword_shift_encrypt,
    nihilist_decrypt,
    nihilist_encrypt,
    phillips_decrypt,
    phillips_encrypt,
    porta_decrypt,
    porta_encrypt,
    ragbaby_decrypt,
    ragbaby_encrypt,
    slidefair_decrypt,
    slidefair_encrypt,
    solitaire_decrypt,
    solitaire_encrypt,
    trithemius_decrypt,
    trithemius_encrypt,
    variant_beaufort_decrypt,
    variant_beaufort_encrypt,
    vernam_decrypt,
    vernam_encrypt,
)


def test_beaufort_roundtrip():
    text = "DEFENDTHEEASTWALLOFTHECASTLE"
    key = "FORTIFICATION"
    ct = beaufort_encrypt(text, key)
    pt = beaufort_decrypt(ct, key)
    assert pt == text
    # Beaufort is self-reciprocal
    assert beaufort_encrypt(ct, key) == text


def test_variant_beaufort_roundtrip():
    text = "DEFENDTHEEASTWALL"
    key = "LEMON"
    ct = variant_beaufort_encrypt(text, key)
    pt = variant_beaufort_decrypt(ct, key)
    assert pt == text


def test_autokey_roundtrip():
    text = "DEFENDTHEEASTWALLOFTHECASTLE"
    key = "KRYPTOS"
    ct = autokey_encrypt(text, key)
    pt = autokey_decrypt(ct, key)
    assert pt == text


def test_gronsfeld_roundtrip():
    text = "EXPLANATION"
    key = 1234
    ct = gronsfeld_encrypt(text, key)
    pt = gronsfeld_decrypt(ct, key)
    assert pt == text


def test_porta_roundtrip():
    text = "DEFENDTHEEASTWALLOFTHECASTLE"
    key = "COMMAND"
    ct = porta_encrypt(text, key)
    pt = porta_decrypt(ct, key)
    assert pt == text


def test_trithemius_roundtrip():
    text = "HELLOWORLD"
    ct = trithemius_encrypt(text)
    pt = trithemius_decrypt(ct)
    assert pt == text


def test_ave_maria_roundtrip():
    text = "ABC"
    ct = ave_maria_encrypt(text)
    pt = ave_maria_decrypt(ct)
    assert pt == text


def test_alberti_roundtrip():
    text = "SECRET"
    ct = alberti_encrypt(text, index_key="M", step=1)
    pt = alberti_decrypt(ct, index_key="M", step=1)
    assert pt == text


def test_bazeries_roundtrip():
    text = "DEFENDTHEEASTWALL"
    key = 3742
    ct = bazeries_encrypt(text, key)
    pt = bazeries_decrypt(ct, key)
    assert pt == text


def test_bellaso_roundtrip():
    text = "ATTACKATDAWN"
    key = "LEMON"
    ct = bellaso_encrypt(text, key)
    pt = bellaso_decrypt(ct, key)
    assert pt == text


def test_chaocipher_roundtrip():
    text = "WELLDONEISBETTERTHANWELLSAID"
    ct = chaocipher_encrypt(text)
    pt = chaocipher_decrypt(ct)
    assert pt == text


def test_nihilist_roundtrip():
    text = "DYNAMITE"
    sq_key = "ZEBRAS"
    add_key = "RUSSIAN"
    nums = nihilist_encrypt(text, sq_key, add_key)
    pt = nihilist_decrypt(nums, sq_key, add_key)
    assert pt == text


def test_phillips_roundtrip():
    text = "PHILIPSCIPHERTEST"
    ct = phillips_encrypt(text, "SECRET")
    pt = phillips_decrypt(ct, "SECRET")
    assert pt == text


def test_ragbaby_roundtrip():
    text = "THIS IS A TEST MESSAGE"
    key = "CIPHER"
    ct = ragbaby_encrypt(text, key)
    pt = ragbaby_decrypt(ct, key)
    assert pt == text


def test_slidefair_roundtrip():
    text = "ATTACK"
    key = "SECRET"
    ct = slidefair_encrypt(text, key)
    pt = slidefair_decrypt(ct, key)
    assert pt == text


def test_keyword_shift_roundtrip():
    text = "HELLOWORLD"
    kw = "KRYPTOS"
    ct = keyword_shift_encrypt(text, kw, shift=3)
    pt = keyword_shift_decrypt(ct, kw, shift=3)
    assert pt == text


def test_jefferson_wheel_roundtrip():
    text = "RETREATNOW"
    ct = jefferson_wheel_encrypt(text, offset=5)
    pt = jefferson_wheel_decrypt(ct, offset=5)
    assert pt == text


def test_solitaire_roundtrip():
    text = "DONOTUSEPC"
    # Known fixed deck (standard sorted 1-54)
    deck = list(range(1, 55))
    ct = solitaire_encrypt(text, deck)
    pt = solitaire_decrypt(ct, deck)
    assert pt == text


def test_vernam_roundtrip():
    data = b"FLAG{one_time_pad_safe}"
    key = b"A_VERY_LONG_SECRET_KEY_123"
    ct = vernam_encrypt(data, key)
    pt = vernam_decrypt(ct, key)
    assert pt == data


def test_crack_beaufort():
    # Longer message with repeating key
    text = "THISISALONGENGLISHTEXTTHATWEAREENCRYPTINGWITHTHEBEAUFORTCIPHERTOVERIFYTHATOURCRACKERWORKSWELL"
    key = "KEY"
    ct = beaufort_encrypt(text, key)
    cand = crack_beaufort(ct, key_length=3)
    assert cand.key == key
    assert cand.confidence > 0.6
