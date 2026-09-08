"""Pedagogical notes and explainability engines for Learner Mode.

Provides technical, mathematical, and architectural explanations for cryptographic,
forensic, steganographic, and binary attack techniques.
"""

from __future__ import annotations

PEDAGOGICAL_KNOWLEDGE_BASE: dict[str, str] = {
    "caesar": (
        "Caesar Cipher Cryptanalysis:\n"
        "The Caesar cipher is a monoalphabetic substitution where each letter in the plaintext "
        "is shifted by a fixed offset k (0 <= k < 26) modulo 26: E(x) = (x + k) mod 26.\n"
        "Because the key space consists of only 25 non-trivial shifts, brute force evaluates all keys. "
        "Each trial decryption is scored against natural language letter frequency distributions "
        "using the Chi-square (χ²) goodness-of-fit statistic or unigram/bigram likelihood."
    ),
    "atbash": (
        "Atbash Cipher:\n"
        "Atbash is an affine cipher with a = -1 and b = -1 modulo 26: E(x) = (25 - x) mod 26. "
        "It is self-inverting (applying it twice yields the original text). It preserves letter "
        "frequencies directly, reversing the alphabet (A <-> Z, B <-> Y)."
    ),
    "affine": (
        "Affine Cipher Cryptanalysis:\n"
        "The Affine cipher encrypts letters using E(x) = (a*x + b) mod 26, where gcd(a, 26) = 1. "
        "The valid key space for 'a' consists of {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25} (Euler's totient φ(26) = 12), "
        "yielding 12 * 26 = 312 total key combinations. Decryption computes D(y) = a^(-1) * (y - b) mod 26."
    ),
    "vigenere": (
        "Vigenère Cipher Cryptanalysis:\n"
        "1. Key Length Determination: Kasiski examination locates repeated n-grams and computes the GCD of their spacings. "
        "Concurrently, the Index of Coincidence (IoC = Σ (f_i * (f_i - 1)) / (N * (N - 1))) tests candidate periods L; "
        "for natural English text, IoC ≈ 0.0667, whereas random polyalphabetic streams yield IoC ≈ 0.0385.\n"
        "2. Column Decomposition: Slicing the ciphertext into L cosets reduces each column to an independent Caesar cipher.\n"
        "3. Frequency Correlation: Chi-square comparison against English letter frequencies recovers each key character."
    ),
    "substitution": (
        "Monoalphabetic Substitution Solver:\n"
        "With a key space of 26! ≈ 4.03 x 10^26, brute-force search is infeasible. "
        "The solver uses stochastic local search (hill climbing) guided by n-gram log-probability fitness: "
        "Score = Σ log10(P(quadgram)). At each iteration, two letters in the key are swapped; "
        "if the quadgram fitness score increases, the mutation is retained."
    ),
    "xor_single": (
        "Single-Byte XOR Cryptanalysis:\n"
        "Every byte of the ciphertext satisfies C_i = P_i ⊕ K for a 1-byte key K (0 <= K <= 255). "
        "The solver computes P'_i = C_i ⊕ K across all 256 keys, evaluating each trial for printable ASCII ratios "
        "and characteristic English quadgram log-likelihoods."
    ),
    "xor_repeating": (
        "Repeating-Key XOR Cryptanalysis:\n"
        "1. Key Length Detection: Normalized Hamming distance (bit differences per byte) between adjacent blocks of length K "
        "is minimized when K is the true key length (or a multiple thereof).\n"
        "2. Transposition & Cracking: Grouping bytes by index modulo K transforms the problem into K independent single-byte XOR instances."
    ),
    "rsa_wiener": (
        "Wiener's Low Private Exponent Attack on RSA:\n"
        "When private exponent d < (1/3) * N^(1/4), the equation e*d - k*φ(N) = 1 implies |e/N - k/d| < 1 / (2 * d^2). "
        "By Legendre's theorem on continued fractions, k/d must appear among the convergents of the continued fraction expansion of e/N. "
        "Testing each convergent allows instant factorization of N."
    ),
    "rsa_boneh_durfee": (
        "Boneh-Durfee Attack on Low Private Exponent RSA:\n"
        "Extends Wiener's bound up to d < N^0.292 using bivariate polynomial root-finding over lattices (Coppersmith's method). "
        "We set f(x, y) = x*(A + y) + 1 ≡ 0 (mod e) where A = N + 1, x = k, and y = -(p + q). "
        "Applying LLL lattice reduction to the bivariate coefficient matrix finds the integer root (x0, y0), recovering (p + q) and factoring N."
    ),
    "rsa_hastad": (
        "Håstad's Broadcast Attack on RSA:\n"
        "When the same message m is encrypted under e distinct public keys (N_1, e), ..., (N_e, e) with gcd(N_i, N_j) = 1: "
        "Chinese Remainder Theorem (CRT) computes C = m^e mod (N_1 * ... * N_e). "
        "Since m < N_i for all i, m^e < N_1 * ... * N_e. Therefore, C holds strictly over the integers, and computing the exact "
        "e-th root m = floor(C^(1/e)) recovers the plaintext without factoring any modulus."
    ),
    "rsa_common_modulus": (
        "RSA Common Modulus Attack:\n"
        "If the same plaintext m is encrypted under two keys sharing modulus N with coprime exponents (gcd(e1, e2) = 1): "
        "Extended Euclidean Algorithm finds integers u, v such that e1*u + e2*v = 1. "
        "Computing c1^u * c2^v mod N = (m^e1)^u * (m^e2)^v mod N = m^(e1*u + e2*v) mod N = m recovers the message."
    ),
    "rsa_coppersmith": (
        "Coppersmith's Small-Roots Method (Howgrave-Graham):\n"
        "Finds small integer roots |x0| < X of a polynomial f(x) ≡ 0 (mod N). "
        "We build an integer lattice whose basis vectors represent polynomial shifts whose roots include x0 modulo N^k. "
        "LLL basis reduction constructs an auxiliary polynomial Q(x) with small coefficients such that |Q(x0)| < N^k; "
        "by Howgrave-Graham's lemma, Q(x0) = 0 strictly over the integers, which is solved by standard polynomial root finding."
    ),
    "rsa_bleichenbacher": (
        "Bleichenbacher's PKCS#1 v1.5 Padding Oracle Attack:\n"
        "Exploits an oracle that reveals whether a decrypted ciphertext begins with 0x00 0x02 (valid PKCS#1 v1.5 padding). "
        "By querying chosen ciphertexts c * s^e mod N for carefully bounded multiplier integers s, the attacker iteratively narrows down "
        "the interval of possible values for the plaintext m until a single candidate remains."
    ),
    "rsa_bellcore": (
        "Bellcore RSA-CRT Fault Injection Attack:\n"
        "In RSA-CRT, the signature s is formed from s_p = m^(d mod p-1) mod p and s_q = m^(d mod q-1) mod q. "
        "If a hardware fault corrupts s_q into s'_q while s_p remains valid, the resulting signature s' satisfies: "
        "s' ≡ s_p (mod p) but s' != s_q (mod q). "
        "Consequently, gcd(s'^e - m, N) = p, factoring the modulus with a single faulty signature."
    ),
    "ecdsa_nonce_bias": (
        "Biased-Nonce ECDSA Private Key Recovery (Hidden Number Problem):\n"
        "In ECDSA, s = k^(-1) * (z + r * d) mod n. If the nonces k have known bias (e.g. upper bits are zero, so k < 2^l): "
        "the relation rearranges to t_i * d - k_i + u_i ≡ 0 (mod n). "
        "This is an instance of Boneh-Venkatesan's Hidden Number Problem, solved by mapping the system into a Kannan embedding lattice "
        "and performing LLL reduction to isolate the private key vector."
    ),
    "mitm": (
        "Meet-in-the-Middle (MITM) Attack:\n"
        "For composition ciphers C = E_k2(E_k1(P)), rather than testing 2^(2k) combinations: "
        "Compute and store in a hash table intermediate states I = E_k1(P) for all candidate k1 (2^k operations). "
        "Then decrypt C backwards: test whether D_k2(C) matches an entry in the hash table. "
        "Reduces time complexity from O(2^(2k)) to O(2^k) at the cost of O(2^k) space."
    ),
    "lsb_stego": (
        "LSB (Least Significant Bit) Steganography:\n"
        "Secret data is encoded directly into the least significant bit(s) of image pixel color channels (R, G, B, A). "
        "Because changing the lowest bit alters color intensity by at most 1/255 (< 0.4%), the difference is imperceptible to the human eye. "
        "Extraction reads bitplanes in raster scanline order, testing permutations of channel orders (RGB, BGR) and bit significance."
    ),
    "apng_stego": (
        "Animated PNG (APNG) Hidden Frames:\n"
        "APNG files contain an animation control chunk (acTL) and frame control/data chunks (fcTL/fdAT). "
        "Standard image viewers frequently display only the default IDAT image or play through frames too rapidly to observe single-frame secrets. "
        "Forensic reconstruction parses every fcTL chunk to isolate hidden frames and anomalous display delays."
    ),
    "docker_whiteout": (
        "Container Image Layer Forensics & Whiteout Markers:\n"
        "In OCI and Docker images, layers are stacked read-only filesystems. Deleting a sensitive file (e.g. credentials, flags) "
        "in a later layer does NOT purge it from earlier layers; the filesystem merely writes an OCI whiteout marker (.wh.<filename>). "
        "Forensic extraction parses the layer tarballs in sequence to recover files that were masked by whiteout markers."
    ),
    "sqlite_carving": (
        "SQLite Database Forensics (Freeblocks and Unallocated Space):\n"
        "When rows or tables in SQLite are deleted, SQLite marks the corresponding page cells as freeblocks or moves pages to the freelist "
        "without zeroing the underlying byte payload. Scanning the unallocated gap between the cell pointer array and the content start "
        "carves remnants of deleted rows and dropped tables."
    ),
    "dns_tunneling": (
        "DNS Covert Channel & Subdomain Exfiltration:\n"
        "Outbound DNS queries (UDP 53) are rarely blocked by strict firewalls. Malware and CTF challenges exfiltrate data "
        "by encoding payloads into subdomain labels (e.g. <hex_data>.tunnel.domain.com). "
        "Reassembly extracts the subdomain labels across consecutive queries, reorders packets, and attempts hex/base64/base32 decoding."
    ),
    "graphql_introspection": (
        "GraphQL Schema Introspection & Field Leakage:\n"
        "GraphQL servers with introspection enabled expose their entire schema via the __schema meta-field. "
        "This reveals all queries, mutations, types, and hidden administrative endpoints. "
        "When introspection is disabled, error-based suggestion algorithms ('Did you mean ...?') allow automated schema recovery (Clairvoyance technique)."
    ),
    "ssti": (
        "Server-Side Template Injection (SSTI):\n"
        "Occurs when user input is concatenated directly into a server-side template rather than passed as context data. "
        "Polyglot probes (${7*7}, {{7*7}}, {{7*'7'}}) fingerprint the engine based on arithmetic evaluation and string coercion. "
        "Exploitation traverses language object introspection (e.g. Python MRO subclasses, Java runtime reflection) to invoke system commands."
    ),
}


def get_pedagogical_note(technique: str, default_summary: str = "") -> str:
    """Finds or constructs a pedagogical note explaining the mechanics of the technique."""
    clean = technique.lower().replace("-", "_").replace(" ", "_")

    # Direct match
    if clean in PEDAGOGICAL_KNOWLEDGE_BASE:
        return PEDAGOGICAL_KNOWLEDGE_BASE[clean]

    # Substring search
    for k, v in PEDAGOGICAL_KNOWLEDGE_BASE.items():
        if k in clean or clean in k:
            return v

    # Keyword check
    keywords = [
        ("vigenere", "vigenere"),
        ("caesar", "caesar"),
        ("atbash", "atbash"),
        ("affine", "affine"),
        ("substitution", "substitution"),
        ("wiener", "rsa_wiener"),
        ("boneh", "rsa_boneh_durfee"),
        ("hastad", "rsa_hastad"),
        ("common_modulus", "rsa_common_modulus"),
        ("coppersmith", "rsa_coppersmith"),
        ("bleichenbacher", "rsa_bleichenbacher"),
        ("bellcore", "rsa_bellcore"),
        ("biased", "ecdsa_nonce_bias"),
        ("mitm", "mitm"),
        ("lsb", "lsb_stego"),
        ("apng", "apng_stego"),
        ("docker", "docker_whiteout"),
        ("sqlite", "sqlite_carving"),
        ("dns", "dns_tunneling"),
        ("graphql", "graphql_introspection"),
        ("template", "ssti"),
        ("ssti", "ssti"),
        ("xor", "xor_single"),
    ]

    for kw, key in keywords:
        if kw in clean:
            return PEDAGOGICAL_KNOWLEDGE_BASE[key]

    if default_summary:
        return f"Analysis Technique: {technique}\n{default_summary}"

    return (
        f"Technique Analysis: {technique}\n"
        "In Learner Mode, Ichnos displays the step-by-step mathematical derivation, "
        "cryptanalytic hypothesis testing, and intermediate states produced during execution."
    )
