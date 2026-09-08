"""Crypto sub-app."""

import typer

import ichnos.crypto.classical.affine as affine
import ichnos.crypto.classical.atbash as atbash
import ichnos.crypto.classical.caesar as caesar
import ichnos.crypto.classical.enigma as enigma_mod
import ichnos.crypto.classical.polyalphabetic as polyalphabetic_mod
import ichnos.crypto.classical.polygraphic as polygraphic_mod
import ichnos.crypto.classical.substitution as substitution
import ichnos.crypto.classical.symboltable as symboltable
import ichnos.crypto.classical.transposition as transposition_mod
import ichnos.crypto.classical.vigenere as vigenere
import ichnos.crypto.ecc as ecc_mod
import ichnos.crypto.ecc.point_recovery as ecc_recovery
import ichnos.crypto.hashing.compute as hash_compute
import ichnos.crypto.hashing.discrete_log as dlog_mod
import ichnos.crypto.hashing.identify as hash_identify
import ichnos.crypto.hashing.length_extension as length_ext_mod
import ichnos.crypto.jwt as jwt_mod
import ichnos.crypto.numtheory as numtheory
import ichnos.crypto.pqc as pqc_mod
import ichnos.crypto.pqc.ntru_solve as ntru_solve
import ichnos.crypto.rsa as rsa_mod
import ichnos.crypto.symmetric.openssl_brute as openssl_brute
import ichnos.crypto.xor.crib_drag as crib_drag
import ichnos.crypto.xor.repeating_key as xor_repeating
import ichnos.crypto.xor.single_byte as xor_single
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)
xor_app = typer.Typer(no_args_is_help=True)
hash_app = typer.Typer(no_args_is_help=True)
math_app = typer.Typer(no_args_is_help=True)
rsa_app = typer.Typer(no_args_is_help=True)
ecc_app = typer.Typer(no_args_is_help=True)
jwt_app = typer.Typer(no_args_is_help=True)
pqc_app = typer.Typer(no_args_is_help=True)
symmetric_app = typer.Typer(no_args_is_help=True)

app.add_typer(symmetric_app, name="symmetric", help="Symmetric cipher analysis and parameter cracking.")
app.add_typer(xor_app, name="xor", help="XOR cipher cracking and analysis.")
app.add_typer(
    hash_app, name="hash", help="Hash identification, computation, and extension attacks."
)
app.add_typer(math_app, name="math", help="Number theory math tools.")
app.add_typer(rsa_app, name="rsa", help="RSA analysis and attacks.")
app.add_typer(ecc_app, name="ecc", help="Elliptic curve cryptography.")
app.add_typer(jwt_app, name="jwt", help="JWT inspection, verification, and attacks.")
app.add_typer(pqc_app, name="pqc", help="Post-quantum cryptography (educational/CTF).")


@app.command("caesar")
def cmd_caesar(
    input_data: str | None = typer.Argument(None),
    shift: int = typer.Option(0, "--shift"),
    brute: bool = typer.Option(False, "--brute"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        text = inp.text
        if not text:
            raise ValueError("Input must be valid text.")

        candidates = []
        raw = None
        if brute:
            cands = caesar.brute_force(text)
            candidates = cands
        else:
            if shift == 0:
                cands = caesar.auto_detect(text)
                candidates = cands
            else:
                if encrypt:
                    raw = caesar.encrypt(text, shift)
                else:
                    raw = caesar.decrypt(text, shift)

        res = Result(candidates=candidates, raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("atbash")
def cmd_atbash(input_data: str | None = typer.Argument(None)):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        raw = atbash.decode(inp.text)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("affine")
def cmd_affine(
    a: int = typer.Option(..., "--a"),
    b: int = typer.Option(..., "--b"),
    input_data: str | None = typer.Argument(None),
    brute: bool = typer.Option(False, "--brute"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        candidates = []
        raw = None
        if brute:
            candidates = affine.brute_force(inp.text)
        else:
            if encrypt:
                raw = affine.encrypt(inp.text, a, b)
            else:
                raw = affine.decrypt(inp.text, a, b)
        res = Result(candidates=candidates, raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("vigenere")
def cmd_vigenere(
    input_data: str | None = typer.Argument(None),
    key: str = typer.Option("", "--key"),
    crack: bool = typer.Option(False, "--crack"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        candidates = []
        raw = None
        if crack:
            candidates = vigenere.crack(inp.text)
        else:
            if not key:
                raise ValueError("Must provide --key or --crack")
            if encrypt:
                raw = vigenere.encrypt(inp.text, key)
            else:
                raw = vigenere.decrypt(inp.text, key)
        res = Result(candidates=candidates, raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("substitution")
def cmd_substitution(
    input_data: str | None = typer.Argument(None),
    iterations: int = typer.Option(5000, "--iterations"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        raw = substitution.solve(inp.text, iterations)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("enigma")
def cmd_enigma(
    input_data: str | None = typer.Argument(None),
    rotors: str = typer.Option("I II III", "--rotors"),
    reflector: str = typer.Option("UKW-B", "--reflector"),
    rings: str = typer.Option("0 0 0", "--rings"),
    positions: str = typer.Option("A A A", "--positions"),
    plugboard: str = typer.Option("", "--plugboard"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        raw = enigma_mod.enigma_encrypt(
            inp.text,
            rotors=rotors,
            reflector=reflector,
            ring_settings=rings,
            positions=positions,
            plugboard=plugboard,
        )
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("playfair")
def cmd_playfair(
    input_data: str | None = typer.Argument(None),
    key: str = typer.Option("", "--key"),
    encrypt: bool = typer.Option(False, "--encrypt"),
    solve: bool = typer.Option(False, "--solve"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        if solve:
            cand = polygraphic_mod.playfair_solve(inp.text)
            res = Result(candidates=[cand])
        else:
            if not key:
                raise ValueError("--key required when not using --solve.")
            if encrypt:
                raw = polygraphic_mod.playfair_encrypt(inp.text, key)
            else:
                raw = polygraphic_mod.playfair_decrypt(inp.text, key)
            res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("railfence")
def cmd_railfence(
    input_data: str | None = typer.Argument(None),
    rails: int = typer.Option(0, "--rails"),
    brute: bool = typer.Option(False, "--brute"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        if brute or rails <= 1:
            cands = transposition_mod.rail_fence_brute(inp.text)
            res = Result(candidates=cands)
        else:
            if encrypt:
                raw = transposition_mod.rail_fence_encrypt(inp.text, rails)
            else:
                raw = transposition_mod.rail_fence_decrypt(inp.text, rails)
            res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("columnar")
def cmd_columnar(
    input_data: str | None = typer.Argument(None),
    key: str = typer.Option(..., "--key"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        if encrypt:
            raw = transposition_mod.columnar_encrypt(inp.text, key)
        else:
            raw = transposition_mod.columnar_decrypt(inp.text, key)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("beaufort")
def cmd_beaufort(
    input_data: str | None = typer.Argument(None),
    key: str = typer.Option(..., "--key"),
    variant: bool = typer.Option(False, "--variant"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        if variant:
            if encrypt:
                raw = polyalphabetic_mod.variant_beaufort_encrypt(inp.text, key)
            else:
                raw = polyalphabetic_mod.variant_beaufort_decrypt(inp.text, key)
        else:
            raw = polyalphabetic_mod.beaufort_encrypt(inp.text, key)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("autokey")
def cmd_autokey(
    input_data: str | None = typer.Argument(None),
    key: str = typer.Option(..., "--key"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        if encrypt:
            raw = polyalphabetic_mod.autokey_encrypt(inp.text, key)
        else:
            raw = polyalphabetic_mod.autokey_decrypt(inp.text, key)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("adfgvx")
def cmd_adfgvx(
    input_data: str | None = typer.Argument(None),
    square_key: str = typer.Option("GERMAN", "--square-key"),
    columnar_key: str = typer.Option("KAISER", "--col-key"),
    encrypt: bool = typer.Option(False, "--encrypt"),
):
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        if encrypt:
            raw = transposition_mod.adfgvx_encrypt(inp.text, square_key, columnar_key)
        else:
            raw = transposition_mod.adfgvx_decrypt(inp.text, square_key, columnar_key)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# XOR Commands
# =============================================================================


@xor_app.command("single")
def cmd_xor_single(input_data: str | None = typer.Argument(None)):
    """Brute force single-byte XOR key."""
    try:
        inp = read_input(input_data)
        candidates = xor_single.brute_force(inp.data)
        res = Result(candidates=candidates)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@xor_app.command("repeating")
def cmd_xor_repeating(
    input_data: str | None = typer.Argument(None),
    key_length: int = typer.Option(0, "--key-length", "-l", help="Key length to use or probe"),
):
    """Break repeating-key XOR via Hamming distance key length estimation."""
    try:
        inp = read_input(input_data)
        if key_length:
            candidates = xor_repeating.crack(inp.data, max_key_len=key_length)
        else:
            candidates = xor_repeating.crack(inp.data)
        res = Result(candidates=candidates)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@xor_app.command("crib")
def cmd_xor_crib(
    input_data: str | None = typer.Argument(None),
    crib: str = typer.Option(..., "--crib", help="Known plaintext crib"),
    target_file: str = typer.Option(
        ..., "--target-file", "--ct2", help="Second ciphertext file or data"
    ),
):
    """Crib dragging across two two-time-pad XOR ciphertexts."""
    try:
        inp1 = read_input(input_data)
        inp2 = read_input(target_file)
        candidates = crib_drag.crib_drag(inp1.data, inp2.data, crib.encode())
        res = Result(candidates=candidates)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("xor-single", hidden=True)(cmd_xor_single)
app.command("xor-repeating", hidden=True)(cmd_xor_repeating)
app.command("xor-crib", hidden=True)(cmd_xor_crib)


# =============================================================================
# Hash Commands
# =============================================================================


@hash_app.command("identify")
def cmd_hash_identify(hash_string: str = typer.Argument(..., help="Hash string to identify")):
    """Identify hash algorithm by format, length, and charset."""
    try:
        findings = hash_identify.identify_hash(hash_string)
        res = Result(findings=findings)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@hash_app.command("compute")
def cmd_hash_compute(
    input_data: str | None = typer.Argument(None),
    algo: str = typer.Option("", "--algo", help="Specific algorithm (md5, sha1, sha256, etc.)"),
):
    """Compute cryptographic hashes of input data."""
    try:
        inp = read_input(input_data)
        if algo:
            raw = hash_compute.compute_hash(inp.data, algo)
        else:
            raw = hash_compute.compute_all(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@hash_app.command("extend")
def cmd_hash_extend(
    orig_hash: str = typer.Option(..., "--hash", help="Original known hash"),
    key_length: int = typer.Option(..., "--key-length", "--len", help="Secret key length in bytes"),
    append_str: str = typer.Option(..., "--append", help="Data string to append"),
    data: str | None = typer.Option(None, "--data", help="Original data (optional)"),
    algo: str = typer.Option("sha256", "--algo", help="Algorithm (sha1 or sha256)"),
):
    """Merkle-Damgard length extension attack (sha1 or sha256)."""
    try:
        data_to_append = append_str.encode("utf-8")
        if algo.lower() == "sha1":
            forged, payload = length_ext_mod.sha1_extend(orig_hash, key_length, data_to_append)
        elif algo.lower() == "sha256":
            forged, payload = length_ext_mod.sha256_extend(orig_hash, key_length, data_to_append)
        else:
            raise ValueError("Algorithm must be sha1 or sha256")

        res = Result(raw_output={"forged_hash": forged, "payload_hex": payload.hex()})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("hash-id", hidden=True)(cmd_hash_identify)
app.command("hash", hidden=True)(cmd_hash_compute)
app.command("length-ext", hidden=True)(cmd_hash_extend)


@app.command("symboltable")
def cmd_symboltable(
    input_data: str | None = typer.Argument(None),
    table: str = typer.Option("", "--table"),
    encode: bool = typer.Option(False, "--encode"),
    list_tables: bool = typer.Option(False, "--list"),
):
    try:
        if list_tables:
            raw = symboltable.list_tables()
            res = Result(raw_output=raw)
            render(res, state.json_mode)
            return

        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")

        if encode:
            raw = symboltable.encode(inp.text, table)
        else:
            raw = symboltable.decode(inp.text, table)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("gcd")
def cmd_math_gcd(a: int = typer.Argument(...), b: int = typer.Argument(...)):
    try:
        raw = numtheory.gcd(a, b)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("modinv")
def cmd_math_modinv(a: int = typer.Argument(...), m: int = typer.Argument(...)):
    try:
        raw = numtheory.mod_inverse(a, m)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("crt")
def cmd_math_crt(
    remainders: str = typer.Option(..., "--remainders"), moduli: str = typer.Option(..., "--moduli")
):
    try:
        rems = [int(x) for x in remainders.split(",")]
        mods = [int(x) for x in moduli.split(",")]
        raw = numtheory.crt(rems, mods)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("isprime")
def cmd_math_isprime(n: int = typer.Argument(...)):
    try:
        raw = numtheory.is_prime(n)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("factor")
def cmd_math_factor(n: int = typer.Argument(...)):
    try:
        raw = numtheory.prime_factorization(n)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@math_app.command("totient")
def cmd_math_totient(n: int = typer.Argument(...)):
    try:
        raw = numtheory.euler_totient(n)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# RSA Commands
# =============================================================================


@rsa_app.command("factor")
def cmd_rsa_factor(n: int = typer.Argument(..., help="Modulus n to factor.")):
    try:
        factors = rsa_mod.factor(n)
        res = Result(raw_output=factors)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@rsa_app.command("wiener")
def cmd_rsa_wiener(
    n: int = typer.Option(..., "--modulus", "-n", help="Modulus n"),
    e: int = typer.Option(..., "--exponent", "-e", help="Public exponent e"),
):
    try:
        d = rsa_mod.wiener_attack(n, e)
        res = Result(raw_output=d)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@rsa_app.command("common-mod")
def cmd_rsa_common_mod(
    n: int = typer.Option(..., "--modulus", "-n", help="Modulus n"),
    e1: int = typer.Option(..., "--e1", help="Exponent 1"),
    e2: int = typer.Option(..., "--e2", help="Exponent 2"),
    c1: int = typer.Option(..., "--c1", help="Ciphertext 1"),
    c2: int = typer.Option(..., "--c2", help="Ciphertext 2"),
):
    try:
        m = rsa_mod.common_modulus_attack(n, e1, e2, c1, c2)
        res = Result(raw_output=m)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@rsa_app.command("audit")
def cmd_rsa_audit(
    n: int = typer.Option(..., "--modulus", "-n", help="RSA modulus"),
    e: int = typer.Option(..., "--exponent", "-e", help="Public exponent"),
    c: int = typer.Option(..., "--ciphertext", "-c", help="Ciphertext"),
):
    """Automated RSA attack suite (small e, Wiener, Fermat, factor.db)."""
    try:
        m = rsa_mod.auto_attack(n, e, c)
        res = Result(raw_output=m)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


rsa_app.command("attack", hidden=True)(cmd_rsa_audit)


@rsa_app.command("common-factor")
def cmd_rsa_common_factor(
    n1: int = typer.Option(..., "--n1", help="First RSA modulus"),
    n2: int = typer.Option(..., "--n2", help="Second RSA modulus"),
    c: int | None = typer.Option(None, "--ciphertext", "-c", help="Ciphertext under n1"),
    e: int = typer.Option(65537, "--exponent", "-e", help="Public exponent (default: 65537)"),
):
    """Common factor attack on two moduli sharing a prime factor."""
    try:
        data = rsa_mod.common_factor_attack(n1, n2, c=c, e=e)
        candidates = []
        if "plaintext" in data:
            from ichnos.core.models import Candidate

            candidates.append(
                Candidate(decoded=data["plaintext"], method="rsa_common_factor", confidence=1.0)
            )
        res = Result(candidates=candidates, raw_output=data)
        render(res, state.json_mode)
    except Exception as e_err:
        print_error(str(e_err))


# =============================================================================
# ECC Commands
# =============================================================================


@ecc_app.command("audit")
def cmd_ecc_audit(
    curve_name: str = typer.Option(
        "secp256k1", "--curve", help="Named curve (secp256k1, nist_p256)"
    ),
):
    try:
        if curve_name not in ecc_mod.CURVES:
            raise ValueError(
                f"Unknown curve {curve_name}. Available: {list(ecc_mod.CURVES.keys())}"
            )
        curve = ecc_mod.CURVES[curve_name]
        audit = ecc_mod.audit_curve(curve)
        res = Result(raw_output=audit)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# JWT Commands
# =============================================================================


@jwt_app.command("decode")
def cmd_jwt_decode(
    token: str = typer.Argument(..., help="JWT token string"),
    verify: bool = typer.Option(False, "--verify"),
    key: str = typer.Option("", "--key"),
):
    try:
        header, payload, sig = jwt_mod.jwt_decode(token, verify=verify, key=key)
        res = Result(raw_output={"header": header, "payload": payload, "signature_hex": sig.hex()})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@jwt_app.command("none")
def cmd_jwt_none(
    token: str = typer.Argument(...),
    alg: str = typer.Option("none", "--alg", help="Algorithm casing (none, None, NONE)"),
):
    try:
        forged = jwt_mod.jwt_attack_none(token, alg_variant=alg)
        res = Result(raw_output=forged)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# PQC Commands
# =============================================================================


@pqc_app.command("hardness")
def cmd_pqc_hardness(
    n: int = typer.Option(256, "--n"),
    q: int = typer.Option(3329, "--q"),
    sigma: float = typer.Option(1.0, "--sigma"),
):
    try:
        est = pqc_mod.estimate_lwe_hardness(n, q, sigma)
        res = Result(raw_output=est)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# Additional Modern Crypto Tools
# =============================================================================


@app.command("dlog")
def cmd_dlog(
    g: int = typer.Option(..., "--g"),
    h: int = typer.Option(..., "--h"),
    p: int = typer.Option(..., "--p"),
    order: int | None = typer.Option(None, "--order"),
):
    """Solve discrete log g^x = h mod p via Pohlig-Hellman."""
    try:
        x = dlog_mod.pohlig_hellman(g, h, p, order=order)
        res = Result(raw_output=x)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# Symmetric Cracking Commands
# =============================================================================


@symmetric_app.command("openssl-brute")
@app.command("openssl-brute")
def cmd_openssl_brute(
    input_file: str = typer.Argument(..., help="Path to OpenSSL-encrypted binary or ciphertext file"),
    password: str | None = typer.Option(None, "--password", "-p", help="Specific password to test"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="Path or name of password wordlist"),
    ciphers: str | None = typer.Option(None, "--ciphers", help="Comma-separated ciphers to test"),
    digests: str | None = typer.Option(None, "--digests", help="Comma-separated digests to test"),
    iterations: str | None = typer.Option(None, "--iterations", help="Comma-separated PBKDF2 iteration counts"),
    markers: str | None = typer.Option(None, "--markers", help="Comma-separated plaintext substrings to search"),
    skip_legacy: bool = typer.Option(False, "--skip-legacy", help="Skip EVP_BytesToKey"),
    skip_pbkdf2: bool = typer.Option(False, "--skip-pbkdf2", help="Skip PBKDF2"),
    workers: int = typer.Option(4, "--workers", help="Worker threads"),
    keep_going: bool = typer.Option(False, "--keep-going", help="Find all valid permutations"),
):
    """Brute-force OpenSSL enc parameters (cipher, digest, KDF, iterations, password)."""
    try:
        c_list = [c.strip() for c in ciphers.split(",")] if ciphers else None
        d_list = [d.strip() for d in digests.split(",")] if digests else None
        it_list = [int(it.strip()) for it in iterations.split(",")] if iterations else None
        m_list = [m.strip().encode() for m in markers.split(",")] if markers else None
        pw_list = [password] if password else None

        results = openssl_brute.crack_openssl_params(
            data_or_path=input_file,
            passwords=pw_list,
            wordlist=wordlist,
            ciphers=c_list,
            digests=d_list,
            iterations=it_list,
            markers=m_list,
            skip_legacy=skip_legacy,
            skip_pbkdf2=skip_pbkdf2,
            workers=workers,
            keep_going=keep_going,
        )
        formatted = [
            {
                "label": r.label,
                "password": r.password,
                "cipher": r.cipher,
                "digest": r.digest,
                "pbkdf2": r.pbkdf2,
                "iterations": r.iterations,
                "confidence": r.confidence,
                "marker": r.marker,
                "plaintext": r.plaintext[:128].decode(errors="replace"),
            }
            for r in results
        ]
        res = Result(raw_output={"success": len(results) > 0, "candidates": formatted})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# ECC Point Recovery Commands
# =============================================================================


@ecc_app.command("recover-curve")
def cmd_ecc_recover_curve(
    px: int = typer.Option(..., "--px", help="Point P x-coordinate"),
    py: int = typer.Option(..., "--py", help="Point P y-coordinate"),
    qx: int = typer.Option(..., "--qx", help="Point Q x-coordinate (2P = Q)"),
    qy: int = typer.Option(..., "--qy", help="Point Q y-coordinate (2P = Q)"),
    rx: int = typer.Option(..., "--rx", help="Point R x-coordinate (2Q = R)"),
    ry: int = typer.Option(..., "--ry", help="Point R y-coordinate (2Q = R)"),
    cx: int | None = typer.Option(None, "--cx", help="Ciphertext point x (C = k*F)"),
    cy: int | None = typer.Option(None, "--cy", help="Ciphertext point y (C = k*F)"),
    k: int | None = typer.Option(None, "--k", help="Scalar multiplier relating C to secret point F"),
    order: int | None = typer.Option(None, "--order", help="Known curve order"),
):
    """Recover elliptic curve modulus p and coefficients (a, b) from 2P=Q, 2Q=R."""
    try:
        c_pt = (cx, cy) if cx is not None and cy is not None else None
        recovered = ecc_recovery.recover_curve_from_doublings(
            P=(px, py),
            Q=(qx, qy),
            R=(rx, ry),
            C=c_pt,
            k=k,
            order=order,
        )
        raw_res = {
            "p": recovered.p,
            "a": recovered.a,
            "b": recovered.b,
            "order": recovered.order,
            "flag": recovered.flag.decode(errors="replace") if recovered.flag else None,
            "decrypted_point": (
                recovered.decrypted_point.x,
                recovered.decrypted_point.y,
            )
            if recovered.decrypted_point
            else None,
        }
        res = Result(raw_output=raw_res)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# PQC NTRU Attack Commands
# =============================================================================


@pqc_app.command("ntru-attack")
def cmd_pqc_ntru_attack(
    pk_coeffs: str = typer.Argument(..., help="Comma-separated public key polynomial coefficients"),
    q: int = typer.Option(..., "--q", help="Modulus q"),
    n: int | None = typer.Option(None, "--n", help="Polynomial dimension (default: len(pk))"),
    ct_hex: str | None = typer.Option(None, "--ct", help="Optional hex ciphertext to decrypt via derived AES key"),
    bound: int = typer.Option(6, "--bound", help="Max coefficient bound for ternary/small vector"),
    block_size: int = typer.Option(45, "--block-size", help="BKZ block size for SageMath"),
):
    """Solve NTRU / negacyclic Ring-LWE instance via block lattice reduction."""
    try:
        pk = [int(x.strip()) for x in pk_coeffs.split(",") if x.strip()]
        ct_bytes = bytes.fromhex(ct_hex) if ct_hex else None
        solution = ntru_solve.solve_ntru_lattice(
            pk=pk,
            q=q,
            n=n,
            ciphertext=ct_bytes,
            bound=bound,
            block_size=block_size,
        )
        if solution:
            raw = {
                "success": True,
                "f": solution.f,
                "g": solution.g,
                "method": solution.method,
                "aes_key": solution.aes_key.hex() if solution.aes_key else None,
                "plaintext": solution.plaintext.decode(errors="replace") if solution.plaintext else None,
            }
        else:
            raw = {"success": False, "message": "No small private key vector found in lattice"}
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))

