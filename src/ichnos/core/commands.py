"""Registration of core and representative commands for registry dispatch."""

from __future__ import annotations

from typing import Any

from ichnos.core.input import read_input
from ichnos.core.models import Candidate, Finding, Input, Result
from ichnos.core.registry import CommandArg, CommandDef, registry

# =============================================================================
# Core Analyze
# =============================================================================


def handle_analyze(
    source: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    findings = registry.query_all(inp)
    return Result(
        command="analyze",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"total_findings": len(findings)},
    )


# =============================================================================
# Core Solve
# =============================================================================


def handle_solve(
    source: str | None = None,
    targets: str | list[str] | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import shlex
    from pathlib import Path

    from ichnos.core.solver import AutoSolver

    target_list: list[str] | None = None
    active_text: str | None = None

    if targets:
        if isinstance(targets, str):
            try:
                raw_parts = shlex.split(targets)
            except ValueError:
                raw_parts = [t for t in targets.split() if t]
        else:
            raw_parts = list(targets)

        target_list = []
        for p in raw_parts:
            try:
                exp = Path(p).expanduser()
                target_list.append(str(exp.resolve()) if exp.exists() else p)
            except Exception:
                target_list.append(p)
    elif source and source != "-":
        try:
            exp_source = Path(source).expanduser()
            if exp_source.exists():
                target_list = [str(exp_source.resolve())]
        except Exception:
            exp_source = None

        if target_list is None:
            try:
                parts = shlex.split(source)
            except ValueError:
                parts = source.split()

            resolved_parts = []
            for p in parts:
                try:
                    exp_p = Path(p).expanduser()
                    if exp_p.exists():
                        resolved_parts.append(str(exp_p.resolve()))
                except Exception:
                    pass

            if resolved_parts:
                target_list = resolved_parts
            else:
                target_list = [source]
    elif active_input:
        if active_input.path:
            try:
                target_list = [str(active_input.path.expanduser().resolve())]
            except Exception:
                target_list = [str(active_input.path)]
        else:
            active_text = active_input.text

    _, result = AutoSolver.solve(targets=target_list, active_text=active_text)
    return result


# =============================================================================
# Binary Strings
# =============================================================================


def handle_binary_strings(
    source: str | None = None,
    min_len: int = 4,
    encoding: str = "all",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    from ichnos.binary.strings import extract_all

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    results = extract_all(inp.data, min_length=min_len, encoding=encoding)
    findings = [
        Finding(
            label=f"String at 0x{off:x}",
            confidence=0.8,
            detail=f"[{enc}] {s}",
            module="binary",
        )
        for off, s, enc in results[:100]  # cap initial view to 100
    ]
    return Result(
        command="binary strings",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"strings_found": len(results), "sample": [s for _, s, _ in results[:50]]},
    )


# =============================================================================
# Crypto Caesar
# =============================================================================


def handle_crypto_caesar(
    source: str | None = None,
    shift: int = 13,
    brute: bool = False,
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.caesar as caesar

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    text = inp.text.strip()

    if brute:
        candidates = caesar.brute_force(text)
        return Result(
            command="crypto caesar --brute",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=candidates,
            raw_output={"total_candidates": len(candidates)},
        )

    out = caesar.encrypt(text, shift) if encrypt else caesar.decrypt(text, shift)
    candidate = Candidate(
        decoded=out,
        method=f"caesar_shift_{shift}",
        key=str(shift),
        confidence=0.9,
    )
    return Result(
        command="crypto caesar",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out, "shift": shift},
    )


# =============================================================================
# Encoding Auto
# =============================================================================


def handle_encoding_auto(
    source: str | None = None,
    max_depth: int = 10,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    from ichnos.encoding.layered import auto_decode

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    candidates = auto_decode(inp.text.strip(), max_depth=max_depth)
    return Result(
        command="encoding auto",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=candidates,
        raw_output={"layers_decoded": len(candidates)},
    )


# =============================================================================
# Stego LSB
# =============================================================================


def handle_stego_lsb(
    file: str | None = None,
    order: str = "RGB",
    bits: int = 1,
    brute: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    from ichnos.stego.image import lsb

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)

    if brute:
        candidates = lsb.brute_force_lsb(inp.data)
        return Result(
            command="stego lsb --brute",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=candidates,
            raw_output={"candidates_count": len(candidates)},
        )

    raw_pix, w, h, ch = lsb.extract_raw_pixels(inp.data)
    extracted = lsb.extract_lsb(
        raw_pix, width=w, height=h, channels=ch, channel_order=order, num_bits=bits
    )
    candidate = Candidate(
        decoded=extracted,
        method=f"lsb_{order}_{bits}bit",
        confidence=0.8,
    )
    return Result(
        command="stego lsb",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"bytes_extracted": len(extracted)},
    )


# =============================================================================
# Crypto Atbash
# =============================================================================


def handle_crypto_atbash(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.atbash as atbash

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = atbash.decode(inp.text)
    candidate = Candidate(decoded=out, method="atbash", confidence=0.8)
    return Result(
        command="crypto atbash",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


# =============================================================================
# Crypto Vigenere
# =============================================================================


def handle_crypto_vigenere(
    source: str | None = None,
    key: str | None = None,
    crack: bool = False,
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.vigenere as vigenere

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    text = inp.text.strip()

    if crack or not key:
        cands = vigenere.crack(text)
        return Result(
            command="crypto vigenere --crack",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=cands,
            raw_output={"total_candidates": len(cands)},
        )

    out = vigenere.encrypt(text, key) if encrypt else vigenere.decrypt(text, key)
    candidate = Candidate(decoded=out, method="vigenere", key=key, confidence=0.85)
    return Result(
        command="crypto vigenere",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out, "key": key},
    )


# =============================================================================
# Crypto XOR Single
# =============================================================================


def handle_crypto_xor_single(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.xor.single_byte as xor_sb

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    candidates = xor_sb.brute_force(inp.data)
    return Result(
        command="crypto xor-single",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=candidates[:20],
        raw_output={"total_candidates": len(candidates)},
    )


# =============================================================================
# Crypto Hash-ID
# =============================================================================


def handle_crypto_hash_id(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.hashing.identify as hash_id

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    findings = hash_id.identify_hash(inp.text.strip())
    return Result(
        command="crypto hash-id",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"hashes_matched": len(findings)},
    )


# =============================================================================
# Encoding Decode / Encode
# =============================================================================


def handle_encoding_decode(
    source: str | None = None,
    format: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.encoding.bases as bases

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if not format:
        candidates = bases.auto_detect(inp.text.strip())
        return Result(
            command="encoding decode",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=candidates,
            raw_output={"candidates_count": len(candidates)},
        )

    fmt_low = format.lower()
    decoder_map = {
        "hex": bases.decode_hex,
        "base16": bases.decode_base16,
        "base32": bases.decode_base32,
        "base58": bases.decode_base58,
        "base64": bases.decode_base64,
        "base64url": bases.decode_base64url,
        "base85": bases.decode_base85,
        "base91": bases.decode_base91,
    }
    if fmt_low not in decoder_map:
        raise ValueError(f"Unsupported format: {format}")

    decoded_bytes = decoder_map[fmt_low](inp.text.strip())
    candidate = Candidate(decoded=decoded_bytes, method=f"decode_{fmt_low}", confidence=0.9)
    return Result(
        command=f"encoding decode --format {format}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": candidate.decoded_str},
    )


# =============================================================================
# Binary Identify, Entropy, ELF
# =============================================================================


def handle_binary_identify(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.identify as binary_id

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    info = binary_id.identify(inp.data)
    findings = [
        Finding(
            label="File Type",
            confidence=1.0,
            detail=f"{info.get('type')} ({info.get('description')})",
            module="binary",
        )
    ]
    return Result(
        command="binary identify",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


def handle_binary_entropy(
    source: str | None = None,
    window: int = 256,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.entropy as entropy_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    summary = entropy_mod.entropy_summary(inp.data)
    findings = [
        Finding(
            label=f"Shannon Entropy: {summary.get('entropy', 0.0):.3f}",
            confidence=1.0,
            detail=f"Packed: {summary.get('likely_packed')}, Encrypted: {summary.get('likely_encrypted')}",
            module="binary",
        )
    ]
    return Result(
        command="binary entropy",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=summary,
    )


def handle_binary_elf(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.elf as elf_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    elf_info = elf_mod.parse_elf(inp.data)
    header = elf_info.get("header", {})
    findings = [
        Finding(
            label="ELF Header",
            confidence=1.0,
            detail=f"{header.get('class')}-bit {header.get('endianness')} {header.get('machine')} entry: 0x{header.get('entry_point', 0):x}",
            module="binary",
        )
    ]
    return Result(
        command="binary elf",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=elf_info,
    )


# =============================================================================
# Stego PNG-Chunks
# =============================================================================


def handle_stego_png_chunks(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.stego.image.png as png_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    chunks = png_mod.parse_chunks(inp.data)
    findings = [
        Finding(
            label=f"Chunk {c.chunk_type}",
            confidence=1.0,
            detail=f"Offset 0x{c.offset:x}, length {c.length} B, crc 0x{c.crc:08x}",
            module="stego",
        )
        for c in chunks
    ]
    return Result(
        command="stego png-chunks",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"chunks_count": len(chunks)},
    )


# =============================================================================
# Forensic ZIP-Inspect
# =============================================================================


def handle_forensic_zip_inspect(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.zip as zip_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    info = zip_mod.inspect_zip(inp.data)
    findings = [
        Finding(
            label="ZIP Archive",
            confidence=1.0,
            detail=f"{info.get('total_entries')} files, encrypted: {zip_mod.is_password_protected(inp.data)}",
            module="forensic",
        )
    ]
    return Result(
        command="forensic zip-inspect",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


def handle_forensic_zip_comments(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.zip as zip_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    comments = zip_mod.extract_comments(inp.data)
    findings = []
    if comments.get("archive_comment"):
        findings.append(
            Finding(
                label="Archive Comment",
                confidence=1.0,
                detail=comments["archive_comment"],
                module="forensic",
            )
        )
    for fn, c in comments.get("file_comments", {}).items():
        findings.append(
            Finding(label=f"Comment ({fn})", confidence=1.0, detail=c, module="forensic")
        )
    return Result(
        command="forensic zip comments",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=comments,
    )


def handle_forensic_zip_crack(
    file: str | None = None,
    wordlist: str = "",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.zip as zip_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    pwd = zip_mod.crack_zip(inp.data, wordlist)
    if pwd:
        cand = Candidate(decoded=f"Password: {pwd}", method="zip_crack", key=pwd, confidence=1.0)
        return Result(command="forensic zip crack", candidates=[cand], raw_output={"password": pwd})
    return Result(
        command="forensic zip crack", status="error", raw_output={"error": "Password not found"}
    )


# =============================================================================
# Section: Reverse Engineering
# =============================================================================


def handle_reverse_disasm(
    source: str | None = None,
    arch: str = "x86_64",
    base: str = "0x1000",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.reverse.disasm as disasm_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    base_addr = int(base, 16) if base.startswith("0x") else int(base)
    insns = disasm_mod.disassemble(inp.data, arch=arch, base_addr=base_addr)
    findings = [
        Finding(
            label=f"{i.mnemonic} {i.op_str}",
            confidence=1.0,
            detail=f"0x{i.address:x}: {i.bytes.hex()}",
            module="reverse",
        )
        for i in insns[:30]
    ]
    raw = "\n".join(str(i) for i in insns)
    return Result(
        command=f"reverse disasm --arch {arch}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"instruction_count": len(insns), "disassembly": raw},
    )


def handle_reverse_cfg(
    source: str | None = None,
    arch: str = "x86_64",
    base: str = "0x1000",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.reverse.cfg as cfg_mod
    import ichnos.reverse.disasm as disasm_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    base_addr = int(base, 16) if base.startswith("0x") else int(base)
    insns = disasm_mod.disassemble(inp.data, arch=arch, base_addr=base_addr)
    blocks = cfg_mod.build_cfg(insns)
    raw = cfg_mod.render_ascii_cfg(blocks)
    return Result(
        command="reverse cfg",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output={"basic_blocks": len(blocks), "cfg": raw},
    )


def handle_reverse_patch(
    file: str | None = None,
    offset: str = "0x0",
    replacement: str | None = None,
    bytes: str | None = None,
    nop: bool = False,
    length: int = 1,
    arch: str = "x86",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.reverse.patch as patch_mod

    inp = (
        active_input
        if (file in (None, "-", "target_placeholder") and active_input)
        else read_input(file)
    )
    off_val = int(offset, 16) if offset.startswith("0x") else int(offset)
    rep = replacement or bytes
    if nop or not rep:
        patched = patch_mod.nop_region(inp.data, off_val, length, arch=arch)
        candidate = Candidate(decoded=patched, method=f"nop_{length}b_{arch}", confidence=1.0)
        return Result(
            command=f"reverse patch --nop --offset {offset} --length {length}",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=[candidate],
            raw_output={"offset": off_val, "length": length, "arch": arch},
        )
    else:
        patch_data = bytes.fromhex(rep.replace(" ", ""))
        patched = patch_mod.patch_bytes(inp.data, off_val, patch_data)
        candidate = Candidate(decoded=patched, method=f"patch_{len(patch_data)}b", confidence=1.0)
        return Result(
            command=f"reverse patch --offset {offset} --bytes {rep}",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=[candidate],
            raw_output={"offset": off_val, "bytes": rep},
        )


def handle_reverse_nop(
    file: str | None = None,
    offset: str = "0x0",
    length: int = 1,
    arch: str = "x86",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.reverse.patch as patch_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    off_val = int(offset, 16) if offset.startswith("0x") else int(offset)
    patched = patch_mod.nop_region(inp.data, off_val, length, arch=arch)
    candidate = Candidate(decoded=patched, method=f"nop_{length}b_{arch}", confidence=1.0)
    return Result(
        command=f"reverse nop --offset {offset} --len {length}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"offset": off_val, "length": length, "arch": arch},
    )


# =============================================================================
# Additional Forensic (tar-inspect, archive-inspect, carve, disk-inspect, timestamp)
# =============================================================================


def handle_forensic_tar_inspect(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.archives as archives_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    raw = archives_mod.inspect_tar(inp.data)
    findings = [
        Finding(
            label=f"Entry: {e.get('name')}",
            confidence=1.0,
            detail=f"Size: {e.get('size')} B, Mode: {e.get('mode')}",
            module="forensic",
        )
        for e in raw.get("entries", [])[:30]
    ]
    return Result(
        command="forensic tar-inspect",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=raw,
    )


def handle_forensic_archive_inspect(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.archives as archives_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    raw = archives_mod.inspect_archive(inp.data)
    findings = [
        Finding(
            label=f"Archive Type: {raw.get('format', 'unknown').upper()}",
            confidence=1.0,
            detail=f"{raw.get('total_entries', 0)} entries, {raw.get('total_uncompressed', 0)} bytes uncompressed",
            module="forensic",
        )
    ]
    return Result(
        command="forensic archive-inspect",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=raw,
    )


def handle_forensic_carve(
    file: str | None = None,
    types: str = "all",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.carver as carver_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    selected = None if types.lower() == "all" else [t.strip() for t in types.split(",")]
    carved = carver_mod.carve_all(inp.data, types=selected)
    findings = [
        Finding(
            label=f"Carved {c.file_type.upper()}",
            confidence=1.0,
            detail=f"Offset 0x{c.offset:x}, size {c.size} B",
            module="forensic",
        )
        for c in carved
    ]
    candidates = [
        Candidate(
            decoded=c.data, method=f"carve_{c.file_type}", key=f"0x{c.offset:x}", confidence=0.9
        )
        for c in carved
    ]
    return Result(
        command="forensic carve",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        candidates=candidates,
        raw_output={"carved_count": len(carved)},
    )


def handle_forensic_disk_inspect(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.filesystem as filesystem_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    info = filesystem_mod.inspect_disk(inp.data)
    findings = []
    if "mbr" in info:
        findings.append(
            Finding(
                label="MBR Partition Table",
                confidence=1.0,
                detail=f"{len(info['mbr'].get('partitions', []))} partitions",
                module="forensic",
            )
        )
    if "gpt" in info:
        findings.append(
            Finding(
                label="GPT Partition Table",
                confidence=1.0,
                detail=f"{len(info['gpt'].get('partitions', []))} partitions",
                module="forensic",
            )
        )
    if "fat" in info:
        findings.append(
            Finding(
                label=f"FAT {info['fat'].get('type')} Filesystem",
                confidence=1.0,
                detail=f"OEM: {info['fat'].get('oem_name')}",
                module="forensic",
            )
        )
    return Result(
        command="forensic disk-inspect",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


def handle_forensic_timestamp(
    value: str | None = None,
    format: str = "auto",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.forensic.timestamps as timestamps_mod

    val = value or (active_input.text.strip() if active_input else "0")
    converted = timestamps_mod.convert_timestamp(val, fmt=format)
    findings = [
        Finding(
            label=f"Timestamp ({converted.get('format', format)})",
            confidence=1.0,
            detail=f"UTC: {converted.get('iso8601_utc')}",
            module="forensic",
        )
    ]
    return Result(
        command=f"forensic timestamp {val}",
        findings=findings,
        raw_output=converted,
    )


# =============================================================================
# Section: PCAP Analysis
# =============================================================================


def handle_pcap_summary(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.pcap.parser as parser_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    packets = parser_mod.read_pcap(inp.data)
    if not packets:
        return Result(command="pcap summary", raw_output={"packets": 0})

    protocols: dict[str, int] = {}
    ip_endpoints: set[str] = set()
    total_bytes = sum(p.length for p in packets)
    start_t = min(p.timestamp for p in packets)
    end_t = max(p.timestamp for p in packets)

    for p in packets:
        proto = p.protocol or "Unknown"
        protocols[proto] = protocols.get(proto, 0) + 1
        if p.ip_src:
            ip_endpoints.add(p.ip_src)
        if p.ip_dst:
            ip_endpoints.add(p.ip_dst)

    summary = {
        "packet_count": len(packets),
        "total_bytes": total_bytes,
        "duration_seconds": round(end_t - start_t, 4),
        "protocols": protocols,
        "unique_ip_endpoints": len(ip_endpoints),
    }
    findings = [
        Finding(
            label=f"Protocol {proto}: {count} pkts",
            confidence=1.0,
            detail=f"{count / len(packets) * 100:.1f}% of capture",
            module="pcap",
        )
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)
    ]
    return Result(
        command="pcap summary",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=summary,
    )


def handle_pcap_flows(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.pcap.flows as flows_mod
    import ichnos.pcap.parser as parser_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    packets = parser_mod.read_pcap(inp.data)
    flows = flows_mod.extract_flows(packets)
    findings = [
        Finding(
            label=f"Flow: {f.get('endpoint_a')} <-> {f.get('endpoint_b')}",
            confidence=1.0,
            detail=f"{f.get('protocol')} | {f.get('packet_count')} pkts ({f.get('byte_count')} B)",
            module="pcap",
        )
        for f in flows[:30]
    ]
    return Result(
        command="pcap flows",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"flow_count": len(flows), "flows": flows},
    )


def handle_pcap_dns(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.pcap.dns as dns_mod
    import ichnos.pcap.parser as parser_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    packets = parser_mod.read_pcap(inp.data)
    queries = dns_mod.extract_dns_queries(packets)
    findings = [
        Finding(
            label=f"DNS Query: {q.get('query')}",
            confidence=1.0,
            detail=f"Type: {q.get('type')}, Client: {q.get('client')}",
            module="pcap",
        )
        for q in queries[:40]
    ]
    return Result(
        command="pcap dns",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"total_queries": len(queries), "queries": queries},
    )


def handle_pcap_credentials(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.pcap.credentials as creds_mod
    import ichnos.pcap.parser as parser_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    packets = parser_mod.read_pcap(inp.data)
    creds = creds_mod.extract_credentials(packets)
    findings = [
        Finding(
            label=f"Credential ({c.get('type')})",
            confidence=1.0,
            detail=f"{c.get('user', '<user>')}:{c.get('pass', '<pass>')} ({c.get('service', 'auth')})",
            module="pcap",
        )
        for c in creds
    ]
    return Result(
        command="pcap credentials",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=creds,
    )


def handle_pcap_http(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.pcap.http as http_mod
    import ichnos.pcap.parser as parser_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    packets = parser_mod.read_pcap(inp.data)
    messages = http_mod.reconstruct_http(packets)
    findings = [
        Finding(
            label=f"HTTP {m.get('method', '')} {m.get('uri', '')}",
            confidence=1.0,
            detail=f"Host: {m.get('host', '')}, Status: {m.get('status', '')}",
            module="pcap",
        )
        for m in messages[:30]
    ]
    return Result(
        command="pcap http",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output={"messages_count": len(messages), "messages": messages},
    )


# =============================================================================
# Section: Network Tools
# =============================================================================


def handle_network_scan(
    host: str = "127.0.0.1",
    ports: str | None = None,
    timeout: float = 0.5,
    workers: int = 20,
    **kwargs: Any,
) -> Result:
    import ichnos.network.scanner as scanner_mod

    results = scanner_mod.scan_ports(host, ports=ports, timeout=timeout, max_workers=workers)
    findings = [
        Finding(
            label=f"Port {item.get('port')}: {item.get('service')}",
            confidence=1.0,
            detail=f"Banner: {item.get('banner', '<none>')}",
            module="network",
        )
        for item in results
    ]
    return Result(
        command=f"network scan {host}",
        findings=findings,
        raw_output={"host": host, "open_ports": results, "count": len(results)},
    )


def handle_network_banner(
    host: str = "127.0.0.1",
    port: int = 80,
    timeout: float = 2.0,
    **kwargs: Any,
) -> Result:
    import ichnos.network.banner as banner_mod

    banner = banner_mod.grab_banner(host, port, timeout=timeout)
    findings = [
        Finding(
            label=f"Banner {host}:{port}",
            confidence=1.0,
            detail=banner,
            module="network",
        )
    ]
    return Result(
        command=f"network banner {host} {port}",
        findings=findings,
        raw_output={"host": host, "port": port, "banner": banner},
    )


def handle_network_tls(
    host: str = "localhost",
    port: int = 443,
    timeout: float = 3.0,
    **kwargs: Any,
) -> Result:
    import ichnos.network.tls as tls_mod

    cert_info = tls_mod.inspect_tls(host, port=port, timeout=timeout)
    findings = [
        Finding(
            label=f"TLS Cert: {cert_info.get('subject', {}).get('CN', host)}",
            confidence=1.0,
            detail=f"Issuer: {cert_info.get('issuer', {}).get('O', 'Unknown')}, Cipher: {cert_info.get('cipher')}",
            module="network",
        )
    ]
    return Result(
        command=f"network tls {host}",
        findings=findings,
        raw_output=cert_info,
    )


# =============================================================================
# Section: Web Tools
# =============================================================================


def handle_web_audit_headers(
    url: str = "http://localhost",
    timeout: float = 5.0,
    **kwargs: Any,
) -> Result:
    import ichnos.web.headers as headers_mod

    report = headers_mod.fetch_and_audit(url, timeout=timeout)
    findings = [
        Finding(
            label=f"Header Audit: {h.get('header')}",
            confidence=0.9 if h.get("status") == "missing" else 1.0,
            detail=f"Status: {h.get('status')}, Recommendation: {h.get('recommendation', '')}",
            module="web",
        )
        for h in report.get("audit", [])
    ]
    return Result(
        command=f"web audit-headers {url}",
        findings=findings,
        raw_output=report,
    )


def handle_web_extract(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.web.extract as extract_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    html_str = inp.data.decode("utf-8", errors="replace")
    extracted = extract_mod.extract_assets(html_str)
    findings = []
    for comment in extracted.get("comments", [])[:10]:
        findings.append(Finding(label="HTML Comment", confidence=0.8, detail=comment, module="web"))
    for email in extracted.get("emails", [])[:10]:
        findings.append(
            Finding(label=f"Email: {email}", confidence=0.9, detail=email, module="web")
        )
    return Result(
        command="web extract",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=extracted,
    )


def handle_web_fuzz(
    url: str = "http://localhost",
    wordlist: str = "",
    status: str | None = None,
    workers: int = 10,
    timeout: float = 3.0,
    **kwargs: Any,
) -> Result:
    from pathlib import Path

    import ichnos.web.fuzz as fuzz_mod

    w_path = Path(wordlist) if wordlist else None
    if w_path and w_path.exists():
        paths = [
            line.strip()
            for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
    else:
        paths = ["admin", "login", "robots.txt", "api", "dashboard", ".git"]

    allowed_statuses = [int(s.strip()) for s in status.split(",")] if status else None
    results = fuzz_mod.fuzz_paths(
        base_url=url,
        wordlist=paths,
        allowed_status=allowed_statuses,
        max_workers=workers,
        timeout=timeout,
    )
    findings = [
        Finding(
            label=f"Endpoint: {item.get('path')} [{item.get('status')}]",
            confidence=1.0,
            detail=f"URL: {item.get('url')} | Size: {item.get('size')} B",
            module="web",
        )
        for item in results
    ]
    return Result(
        command=f"web fuzz {url}",
        findings=findings,
        raw_output={"base_url": url, "count": len(results), "endpoints": results},
    )


# =============================================================================
# Section: OSINT Tools
# =============================================================================


def handle_osint_dns(
    domain: str = "example.com",
    types: str | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.osint.dns_lookup as dns_mod

    req_types = [t.strip().upper() for t in types.split(",")] if types else None
    res_data = dns_mod.resolve_domain(domain, record_types=req_types)
    findings = []
    for rtype, records in res_data.get("records", {}).items():
        for rec in records:
            findings.append(
                Finding(label=f"DNS {rtype}", confidence=1.0, detail=str(rec), module="osint")
            )
    return Result(
        command=f"osint dns {domain}",
        findings=findings,
        raw_output=res_data,
    )


def handle_osint_whois(
    domain: str = "example.com",
    timeout: float = 5.0,
    **kwargs: Any,
) -> Result:
    import ichnos.osint.whois as whois_mod

    info = whois_mod.lookup_whois(domain, timeout=timeout)
    findings = [
        Finding(
            label=f"WHOIS Registrar: {info.get('registrar', 'Unknown')}",
            confidence=1.0,
            detail=f"Created: {info.get('creation_date')}, Expires: {info.get('expiration_date')}",
            module="osint",
        )
    ]
    return Result(
        command=f"osint whois {domain}",
        findings=findings,
        raw_output=info,
    )


# =============================================================================
# Section: Password Tools
# =============================================================================


def handle_password_mutate(
    word: str = "",
    leet: bool = True,
    casing: bool = True,
    affixes: bool = True,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.password.mutator as mutator_mod

    target_word = word or (active_input.text.strip() if active_input else "")
    mutations = mutator_mod.mutate_word(
        target_word, include_leet=leet, include_casing=casing, include_affixes=affixes
    )
    candidates = [
        Candidate(decoded=m, method="rule_mutation", confidence=0.8) for m in mutations[:30]
    ]
    return Result(
        command=f"password mutate {target_word}",
        candidates=candidates,
        raw_output={"base": target_word, "count": len(mutations), "mutations": mutations[:100]},
    )


def handle_password_generate(
    words: str = "",
    suffixes: str = "!,123,2024",
    delimiter: str = "",
    **kwargs: Any,
) -> Result:
    import ichnos.password.wordlist as wordlist_mod

    w_list = [w.strip() for w in words.split(",") if w.strip()]
    s_list = [s.strip() for s in suffixes.split(",") if s.strip()]
    combined = wordlist_mod.combine_lists([w_list, s_list], delimiter=delimiter)
    candidates = [
        Candidate(decoded=w, method="wordlist_combo", confidence=0.7) for w in combined[:30]
    ]
    return Result(
        command="password generate",
        candidates=candidates,
        raw_output={"count": len(combined), "wordlist": combined[:100]},
    )


def handle_password_crack(
    target_hash: str = "",
    wordlist: str = "",
    algo: str = "auto",
    mutate: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    from pathlib import Path

    import ichnos.password.crack as crack_mod

    h = target_hash or (active_input.text.strip() if active_input else "")
    w_path = Path(wordlist)
    if not w_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    words = [
        line.strip()
        for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    cracked = crack_mod.crack_hash(h, words, algorithm=algo, apply_rules=mutate)
    if cracked:
        candidate = Candidate(decoded=cracked, method=f"crack_{algo}", confidence=1.0)
        return Result(
            command=f"password crack {h}",
            candidates=[candidate],
            raw_output={"hash": h, "cracked": True, "plaintext": cracked},
        )
    return Result(
        command=f"password crack {h}",
        raw_output={"hash": h, "cracked": False, "plaintext": None},
    )


# =============================================================================
# Additional Crypto (affine, enigma, symboltable)
# =============================================================================


def handle_crypto_affine(
    source: str | None = None,
    a: int = 1,
    b: int = 0,
    brute: bool = False,
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.affine as affine_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if brute:
        cands = affine_mod.brute_force(inp.text)
        return Result(
            command="crypto affine --brute",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=cands,
            raw_output={"total_candidates": len(cands)},
        )

    out = affine_mod.encrypt(inp.text, a, b) if encrypt else affine_mod.decrypt(inp.text, a, b)
    candidate = Candidate(decoded=out, method=f"affine_a{a}_b{b}", confidence=0.85)
    return Result(
        command=f"crypto affine --a {a} --b {b}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


def handle_crypto_enigma(
    source: str | None = None,
    rotors: str = "I II III",
    reflector: str = "UKW-B",
    rings: str = "0 0 0",
    positions: str = "A A A",
    plugboard: str = "",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.enigma as enigma_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = enigma_mod.enigma_encrypt(
        inp.text,
        rotors=rotors,
        reflector=reflector,
        ring_settings=rings,
        positions=positions,
        plugboard=plugboard,
    )
    candidate = Candidate(decoded=out, method="enigma_m3", confidence=0.9)
    return Result(
        command="crypto enigma",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


def handle_crypto_symboltable(
    source: str | None = None,
    table: str = "morse",
    encode: bool = False,
    list_tables: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.symboltable as sym_mod

    if list_tables:
        tables = sym_mod.list_tables()
        findings = [
            Finding(label=f"Table: {t}", confidence=1.0, detail=t, module="crypto")
            for t in tables[:40]
        ]
        return Result(command="crypto symboltable --list", findings=findings, raw_output=tables)

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = sym_mod.encode(inp.text, table) if encode else sym_mod.decode(inp.text, table)
    candidate = Candidate(decoded=str(out), method=f"symboltable_{table}", confidence=0.9)
    return Result(
        command=f"crypto symboltable --table {table}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


# =============================================================================
# Additional Encoding (morse, esolang)
# =============================================================================


def handle_encoding_morse(
    source: str | None = None,
    encode: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.encoding.morse as morse_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = morse_mod.encode(inp.text) if encode else morse_mod.decode(inp.text)
    candidate = Candidate(decoded=out, method="morse", confidence=0.9)
    return Result(
        command="encoding morse",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


def handle_encoding_esolang(
    source: str | None = None,
    lang: str = "brainfuck",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.encoding.esolang as esolang_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    lang_low = lang.lower()
    if lang_low == "brainfuck":
        out = esolang_mod.interpret_brainfuck(inp.text)
    elif lang_low == "ook":
        out = esolang_mod.interpret_ook(inp.text)
    elif lang_low == "deadfish":
        out = esolang_mod.interpret_deadfish(inp.text)
    elif lang_low == "whitespace":
        out = esolang_mod.interpret_whitespace(inp.text)
    elif lang_low == "lolcode":
        out = esolang_mod.interpret_lolcode(inp.text)
    elif lang_low == "jsfuck":
        out = esolang_mod.interpret_jsfuck(inp.text)
    else:
        raise ValueError(f"Unsupported esolang: {lang}")

    candidate = Candidate(decoded=out, method=f"esolang_{lang_low}", confidence=0.95)
    return Result(
        command=f"encoding esolang --lang {lang}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"output": out},
    )


# =============================================================================
# Additional Binary (pe, macho, packer)
# =============================================================================


def handle_binary_pe(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.pe as pe_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    info = pe_mod.parse_pe(inp.data)
    findings = [
        Finding(
            label=f"PE {info.get('arch')}-bit",
            confidence=1.0,
            detail=f"Sections: {len(info.get('sections', []))}, Entry: 0x{info.get('entry_point', 0):x}",
            module="binary",
        )
    ]
    return Result(
        command="binary pe",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


def handle_binary_macho(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.macho as macho_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    info = macho_mod.parse_macho(inp.data)
    findings = [
        Finding(
            label=f"Mach-O {info.get('cpu_type')}",
            confidence=1.0,
            detail=f"{info.get('bits')}-bit, Load Commands: {info.get('ncmds')}",
            module="binary",
        )
    ]
    return Result(
        command="binary macho",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


def handle_binary_packer(
    source: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.binary.packer as packer_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    info = packer_mod.detect_packer(inp.data)
    findings = [
        Finding(
            label=f"Packer: {info.get('packer', 'None')}",
            confidence=info.get("confidence", 0.5),
            detail=info.get("description", ""),
            module="binary",
        )
    ]
    return Result(
        command="binary packer",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=info,
    )


# =============================================================================
# Additional Stego (spectrogram, morse-audio, text-null)
# =============================================================================


def handle_stego_spectrogram(
    file: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.stego.audio.spectrogram as spec_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    ascii_spec = spec_mod.render_ascii_spectrogram(inp.data)
    return Result(
        command="stego spectrogram",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output={"spectrogram": ascii_spec},
    )


def handle_stego_morse_audio(
    file: str | None = None,
    threshold: float | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.stego.audio.morse as morse_audio_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    text = morse_audio_mod.detect_morse(inp.data, threshold=threshold)
    candidate = Candidate(decoded=text, method="audio_morse", confidence=0.85)
    return Result(
        command="stego morse-audio",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"decoded": text},
    )


def handle_stego_text_null(
    source: str | None = None,
    mode: str = "first-letter",
    n: int = 2,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.stego.text as text_stego_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if mode == "first-letter":
        out = text_stego_mod.null_cipher_first_letter(inp.text)
    elif mode == "nth-letter":
        out = text_stego_mod.null_cipher_nth_letter(inp.text, n=n)
    elif mode == "first-sentence":
        out = text_stego_mod.null_cipher_first_sentence(inp.text)
    else:
        out = text_stego_mod.acrostic(inp.text)

    candidate = Candidate(decoded=out, method=f"null_cipher_{mode}", confidence=0.8)
    return Result(
        command=f"stego text-null --mode {mode}",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[candidate],
        raw_output={"extracted": out},
    )


def handle_crypto_substitution(
    source: str | None = None,
    iterations: int = 5000,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.substitution as sub_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    res = sub_mod.solve(inp.text, iterations=iterations)
    cand = Candidate(
        decoded=res.get("plaintext", ""),
        method="substitution",
        key=res.get("key", ""),
        confidence=res.get("confidence", 0.8),
    )
    return Result(
        command="crypto substitution",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[cand],
        raw_output=res,
    )


def handle_crypto_playfair(
    source: str | None = None,
    key: str = "",
    encrypt: bool = False,
    solve: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.polygraphic as poly_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if solve:
        cand = poly_mod.playfair_solve(inp.text)
        return Result(
            command="crypto playfair --solve",
            input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
            candidates=[cand],
            raw_output={"solved": True, "plaintext": cand.decoded},
        )
    out = (
        poly_mod.playfair_encrypt(inp.text, key)
        if encrypt
        else poly_mod.playfair_decrypt(inp.text, key)
    )
    return Result(
        command="crypto playfair",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[Candidate(decoded=out, method="playfair", key=key, confidence=0.85)],
        raw_output={"result": out, "key": key},
    )


def handle_crypto_railfence(
    source: str | None = None,
    rails: int = 0,
    brute: bool = False,
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.transposition as trans_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if brute or rails <= 1:
        cands = trans_mod.rail_fence_brute(inp.text)
        return Result(
            command="crypto railfence --brute",
            candidates=cands,
            raw_output={"candidates": len(cands)},
        )
    out = (
        trans_mod.rail_fence_encrypt(inp.text, rails)
        if encrypt
        else trans_mod.rail_fence_decrypt(inp.text, rails)
    )
    return Result(
        command="crypto railfence",
        candidates=[Candidate(decoded=out, method="railfence", key=str(rails), confidence=0.85)],
        raw_output={"result": out, "rails": rails},
    )


def handle_crypto_columnar(
    source: str | None = None,
    key: str = "",
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.transposition as trans_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = (
        trans_mod.columnar_encrypt(inp.text, key)
        if encrypt
        else trans_mod.columnar_decrypt(inp.text, key)
    )
    return Result(
        command="crypto columnar",
        candidates=[Candidate(decoded=out, method="columnar", key=key, confidence=0.85)],
        raw_output={"result": out, "key": key},
    )


def handle_crypto_beaufort(
    source: str | None = None,
    key: str = "",
    variant: bool = False,
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.polyalphabetic as poly_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if variant:
        out = (
            poly_mod.variant_beaufort_encrypt(inp.text, key)
            if encrypt
            else poly_mod.variant_beaufort_decrypt(inp.text, key)
        )
    else:
        out = poly_mod.beaufort_encrypt(inp.text, key)
    return Result(
        command="crypto beaufort",
        candidates=[Candidate(decoded=out, method="beaufort", key=key, confidence=0.85)],
        raw_output={"result": out, "key": key},
    )


def handle_crypto_autokey(
    source: str | None = None,
    key: str = "",
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.polyalphabetic as poly_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = (
        poly_mod.autokey_encrypt(inp.text, key)
        if encrypt
        else poly_mod.autokey_decrypt(inp.text, key)
    )
    return Result(
        command="crypto autokey",
        candidates=[Candidate(decoded=out, method="autokey", key=key, confidence=0.85)],
        raw_output={"result": out, "key": key},
    )


def handle_crypto_adfgvx(
    source: str | None = None,
    square_key: str = "GERMAN",
    columnar_key: str = "KAISER",
    encrypt: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.classical.transposition as trans_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = (
        trans_mod.adfgvx_encrypt(inp.text, square_key, columnar_key)
        if encrypt
        else trans_mod.adfgvx_decrypt(inp.text, square_key, columnar_key)
    )
    return Result(
        command="crypto adfgvx",
        candidates=[
            Candidate(
                decoded=out, method="adfgvx", key=f"{square_key}:{columnar_key}", confidence=0.85
            )
        ],
        raw_output={"result": out, "square_key": square_key, "columnar_key": columnar_key},
    )


def handle_crypto_xor_repeating(
    source: str | None = None,
    key_length: int = 0,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.xor.repeating_key as xor_rep

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    cands = (
        xor_rep.crack(inp.data, max_key_len=key_length) if key_length else xor_rep.crack(inp.data)
    )
    return Result(
        command="crypto xor repeating",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=cands if isinstance(cands, list) else [cands],
        raw_output={"candidates": len(cands) if isinstance(cands, list) else 1},
    )


def handle_crypto_xor_crib(
    source: str | None = None,
    crib: str = "",
    target_file: str | None = None,
    ct2: str | None = None,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.xor.crib_drag as crib_mod

    inp1 = active_input if (source in (None, "-") and active_input) else read_input(source)
    other = target_file or ct2
    inp2 = read_input(other)
    cands = crib_mod.crib_drag(inp1.data, inp2.data, crib.encode())
    return Result(command="crypto xor crib", candidates=cands, raw_output={"matches": len(cands)})


def handle_crypto_hash_compute(
    source: str | None = None,
    algo: str = "",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.hashing.compute as h_comp

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    if algo:
        out = h_comp.compute_hash(inp.data, algo)
        raw = {algo: out}
    else:
        raw = h_comp.compute_all(inp.data)
    findings = [
        Finding(label=f"Hash ({k})", confidence=1.0, detail=v, module="crypto")
        for k, v in raw.items()
    ]
    return Result(
        command="crypto hash compute",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        findings=findings,
        raw_output=raw,
    )


def handle_crypto_hash_extend(
    orig_hash: str = "",
    key_length: int = 0,
    append: str = "",
    algo: str = "sha256",
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.hashing.length_extension as le_mod

    app_b = append.encode("utf-8")
    if algo.lower() == "sha1":
        forged, payload = le_mod.sha1_extend(orig_hash, key_length, app_b)
    else:
        forged, payload = le_mod.sha256_extend(orig_hash, key_length, app_b)
    return Result(
        command="crypto hash extend",
        raw_output={"forged_hash": forged, "payload_hex": payload.hex()},
    )


def handle_crypto_math_gcd(a: int = 0, b: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    val = nt.gcd(int(a), int(b))
    return Result(command="crypto math gcd", raw_output={"gcd": val})


def handle_crypto_math_modinv(a: int = 0, m: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    val = nt.mod_inverse(int(a), int(m))
    return Result(command="crypto math modinv", raw_output={"modinv": val})


def handle_crypto_math_crt(remainders: str = "", moduli: str = "", **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    rems = [int(x.strip()) for x in remainders.split(",") if x.strip()]
    mods = [int(x.strip()) for x in moduli.split(",") if x.strip()]
    val = nt.crt(rems, mods)
    return Result(command="crypto math crt", raw_output={"crt": val})


def handle_crypto_math_isprime(n: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    val = nt.is_prime(int(n))
    return Result(command="crypto math isprime", raw_output={"is_prime": val})


def handle_crypto_math_factor(n: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    val = nt.prime_factorization(int(n))
    return Result(command="crypto math factor", raw_output={"factors": val})


def handle_crypto_math_totient(n: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.numtheory as nt

    val = nt.euler_totient(int(n))
    return Result(command="crypto math totient", raw_output={"totient": val})


def handle_crypto_rsa_factor(n: int = 0, **kwargs: Any) -> Result:
    import ichnos.crypto.rsa as rsa_mod

    val = rsa_mod.factor(int(n))
    return Result(command="crypto rsa factor", raw_output=val)


def handle_crypto_rsa_wiener(
    modulus: int = 0, exponent: int = 0, n: int = 0, e: int = 0, **kwargs: Any
) -> Result:
    import ichnos.crypto.rsa as rsa_mod

    mod = int(modulus or n)
    exp = int(exponent or e)
    val = rsa_mod.wiener_attack(mod, exp)
    return Result(command="crypto rsa wiener", raw_output=val)


def handle_crypto_rsa_common_mod(
    modulus: int = 0, n: int = 0, e1: int = 0, e2: int = 0, c1: int = 0, c2: int = 0, **kwargs: Any
) -> Result:
    import ichnos.crypto.rsa as rsa_mod

    mod = int(modulus or n)
    val = rsa_mod.common_modulus_attack(mod, int(e1), int(e2), int(c1), int(c2))
    return Result(command="crypto rsa common-mod", raw_output=val)


def handle_crypto_rsa_common_factor(
    n1: int = 0,
    n2: int = 0,
    ciphertext: int | None = None,
    c: int | None = None,
    exponent: int = 65537,
    e: int = 65537,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.rsa as rsa_mod

    ct = ciphertext if ciphertext is not None else c
    exp = int(exponent if exponent != 65537 else e)
    val = rsa_mod.common_factor_attack(
        int(n1), int(n2), c=int(ct) if ct is not None else None, e=exp
    )
    candidates = []
    if "plaintext" in val:
        candidates.append(
            Candidate(decoded=val["plaintext"], method="rsa_common_factor", confidence=1.0)
        )
    return Result(command="crypto rsa common-factor", candidates=candidates, raw_output=val)


def handle_crypto_rsa_audit(
    modulus: int = 0,
    n: int = 0,
    exponent: int = 0,
    e: int = 0,
    ciphertext: int = 0,
    c: int = 0,
    **kwargs: Any,
) -> Result:
    import ichnos.crypto.rsa as rsa_mod

    val = rsa_mod.auto_attack(int(modulus or n), int(exponent or e), int(ciphertext or c))
    return Result(command="crypto rsa audit", raw_output=val)


def handle_crypto_ecc_audit(curve: str = "secp256k1", **kwargs: Any) -> Result:
    import ichnos.crypto.ecc as ecc_mod

    if curve not in ecc_mod.CURVES:
        return Result(
            command="crypto ecc audit",
            status="error",
            raw_output={"error": f"Unknown curve {curve}"},
        )
    audit = ecc_mod.audit_curve(ecc_mod.CURVES[curve])
    return Result(command="crypto ecc audit", raw_output=audit)


def handle_crypto_jwt_decode(
    token: str = "", verify: bool = False, key: str = "", **kwargs: Any
) -> Result:
    import ichnos.crypto.jwt as jwt_mod

    header, payload, sig = jwt_mod.jwt_decode(token, verify=verify, key=key)
    return Result(
        command="crypto jwt decode",
        raw_output={"header": header, "payload": payload, "signature_hex": sig.hex()},
    )


def handle_crypto_jwt_none(token: str = "", alg: str = "none", **kwargs: Any) -> Result:
    import ichnos.crypto.jwt as jwt_mod

    forged = jwt_mod.jwt_attack_none(token, alg_variant=alg)
    return Result(command="crypto jwt none", raw_output=forged)


def handle_crypto_pqc_hardness(
    n: int = 256, q: int = 3329, sigma: float = 1.0, **kwargs: Any
) -> Result:
    import ichnos.crypto.pqc as pqc_mod

    est = pqc_mod.estimate_lwe_hardness(int(n), int(q), float(sigma))
    return Result(command="crypto pqc hardness", raw_output=est)


def handle_crypto_dlog(
    g: int = 0, h: int = 0, p: int = 0, order: int | None = None, **kwargs: Any
) -> Result:
    import ichnos.crypto.hashing.discrete_log as dlog_mod

    ord_val = int(order) if order is not None else None
    x = dlog_mod.pohlig_hellman(int(g), int(h), int(p), order=ord_val)
    return Result(command="crypto dlog", raw_output=x)


def handle_stego_jpeg(
    file: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.image.jpeg as jpeg_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    raw = jpeg_mod.inspect_jpeg(inp.data)
    return Result(
        command="stego jpeg",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output=raw,
    )


def handle_stego_exif(
    file: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.image.channels as ch_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    raw = ch_mod.extract_exif_from_image(inp.data)
    return Result(
        command="stego exif",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output=raw,
    )


def handle_stego_channels(
    file: str | None = None, channels: int = 3, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.image.channels as ch_mod
    import ichnos.stego.image.lsb as lsb_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    if inp.data.startswith(b"\x89PNG\r\n\x1a\n"):
        pixels, _, _, detected_channels = lsb_mod.extract_raw_pixels(inp.data)
        raw = ch_mod.analyze_channels(pixels, channels=detected_channels)
    else:
        raw = ch_mod.analyze_channels(inp.data, channels=int(channels))
    return Result(
        command="stego channels",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output=raw,
    )


def handle_stego_steghide(
    file: str | None = None,
    passphrase: str | None = None,
    wordlist: str | None = None,
    extract: bool = False,
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    from pathlib import Path

    import ichnos.stego.image.steghide as sh_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    if wordlist:
        words = [
            w.strip()
            for w in Path(wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()
            if w.strip()
        ]
        res = sh_mod.crack_steghide(inp.data, words)
        raw = {"cracked": bool(res), "passphrase": res[0] if res else None}
    elif extract or passphrase is not None:
        pwd = passphrase or ""
        ext = sh_mod.extract_steghide(inp.data, passphrase=pwd)
        raw = {
            "extracted": bool(ext),
            "payload": ext.decode("latin-1", errors="replace") if ext else None,
        }
    else:
        raw = sh_mod.inspect_steghide_artifacts(inp.data)
    return Result(
        command="stego steghide",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output=raw,
    )


def handle_stego_text_acrostic(
    source: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.text as text_stego_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    out = text_stego_mod.acrostic(inp.text)
    return Result(
        command="stego text acrostic",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=[Candidate(decoded=out, method="acrostic", confidence=0.8)],
        raw_output={"acrostic": out},
    )


def handle_stego_text_reverse(
    source: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.text as text_stego_mod

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    cand = text_stego_mod.detect_reverse(inp.text)
    cands = [cand] if cand else []
    return Result(
        command="stego text reverse",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        candidates=cands,
        raw_output={"candidate": cand.decoded if cand else None},
    )


def handle_stego_audio_info(
    file: str | None = None, active_input: Input | None = None, **kwargs: Any
) -> Result:
    import ichnos.stego.audio.wav as wav_mod

    inp = active_input if (file in (None, "-") and active_input) else read_input(file)
    meta = wav_mod.get_metadata(inp.data)
    return Result(
        command="stego audio info",
        input_summary=f"{inp.detected_type} ({len(inp.data)} B)",
        raw_output=meta,
    )


def handle_osint_subdomains(
    domain: str = "example.com",
    crt: bool = True,
    wordlist: str | None = None,
    workers: int = 20,
    **kwargs: Any,
) -> Result:
    from pathlib import Path

    import ichnos.osint.subdomains as sd_mod

    w_list = None
    if wordlist and Path(wordlist).exists():
        w_list = [
            w.strip()
            for w in Path(wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()
            if w.strip()
        ]
    subs = sd_mod.discover_subdomains(domain, use_crt=crt, wordlist=w_list, workers=workers)
    findings = [
        Finding(label="Subdomain", confidence=0.95, detail=s, module="osint") for s in sorted(subs)
    ]
    return Result(
        command=f"osint subdomains {domain}",
        findings=findings,
        raw_output={"subdomains": sorted(subs)},
    )


def handle_encoding_encode(
    source: str | None = None,
    format: str = "base64",
    active_input: Input | None = None,
    **kwargs: Any,
) -> Result:
    import ichnos.encoding.bases as bases
    import ichnos.encoding.text as text_enc

    inp = active_input if (source in (None, "-") and active_input) else read_input(source)
    fmt = format.lower().strip()
    data = inp.data
    text = inp.text
    if fmt in ("b64", "base64"):
        out = bases.encode_base64(data)
    elif fmt in ("hex", "base16"):
        out = bases.encode_hex(data)
    elif fmt == "base32":
        out = bases.encode_base32(data)
    elif fmt == "base58":
        out = bases.encode_base58(data)
    elif fmt == "base85":
        out = bases.encode_base85(data)
    elif fmt == "base91":
        out = bases.encode_base91(data)
    elif fmt == "url":
        out = text_enc.url_encode(text)
    elif fmt == "html":
        out = text_enc.html_encode(text)
    else:
        return Result(
            command="encoding encode",
            status="error",
            raw_output={"error": f"Unsupported format: {format}"},
        )
    return Result(
        command="encoding encode",
        candidates=[Candidate(decoded=out, method=f"encode_{fmt}", confidence=1.0)],
        raw_output={"encoded": out, "format": fmt},
    )


def register_all_commands() -> None:
    """Registers representative and core commands into the registry."""
    # 1. Analyze & Solve
    registry.register_command(
        CommandDef(
            module="core",
            command="analyze",
            handler=handle_analyze,
            description="Automatic multi-engine triage and heuristic analysis",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=False,
                    is_path=True,
                    description="Input file or '-' for stdin",
                )
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="core",
            command="solve",
            handler=handle_solve,
            description="Autonomously solve CTF challenges across crypto, forensics, and encoding",
            is_long_running=True,
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=False,
                    is_path=True,
                    description="Challenge file, directory, or text",
                ),
            ],
        )
    )

    # 2. Binary
    registry.register_command(
        CommandDef(
            module="binary",
            command="strings",
            handler=handle_binary_strings,
            description="Extract printable strings from binary data",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file to scan",
                ),
                CommandArg(
                    name="min_len",
                    type=int,
                    default=4,
                    is_option=True,
                    short_flag="-n",
                    description="Minimum string length",
                ),
                CommandArg(
                    name="encoding",
                    type=str,
                    default="all",
                    is_option=True,
                    choices=["ascii", "utf16", "all"],
                    description="Encoding",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="binary",
            command="identify",
            handler=handle_binary_identify,
            description="Identify file type and architecture",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="File to identify",
                )
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="binary",
            command="entropy",
            handler=handle_binary_entropy,
            description="Shannon entropy and packing analysis",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="File to inspect",
                ),
                CommandArg(
                    name="window", type=int, default=256, is_option=True, description="Window size"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="binary",
            command="elf",
            handler=handle_binary_elf,
            description="Parse ELF executable headers and symbols",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ELF file",
                ),
            ],
        )
    )

    # 3. Crypto
    registry.register_command(
        CommandDef(
            module="crypto",
            command="caesar",
            handler=handle_crypto_caesar,
            description="Caesar cipher shift encryption, decryption, and brute-force",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Ciphertext or plaintext",
                ),
                CommandArg(
                    name="shift",
                    type=int,
                    default=13,
                    is_option=True,
                    short_flag="-s",
                    description="Shift offset",
                ),
                CommandArg(
                    name="brute",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-b",
                    description="Brute-force all shifts",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt instead of decrypt",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="atbash",
            handler=handle_crypto_atbash,
            description="Atbash reciprocal substitution cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Ciphertext or plaintext",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="vigenere",
            handler=handle_crypto_vigenere,
            description="Vigenère polyalphabetic cipher cracking, decryption, and encryption",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Ciphertext or plaintext",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-k",
                    description="Key",
                ),
                CommandArg(
                    name="crack",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-c",
                    description="Auto-crack key",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt instead of decrypt",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor-single",
            handler=handle_crypto_xor_single,
            description="Brute-force single-byte XOR cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Data to brute-force",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor",
            subcommand="single",
            handler=handle_crypto_xor_single,
            description="Brute-force single-byte XOR cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Data to brute-force",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="hash-id",
            handler=handle_crypto_hash_id,
            description="Identify cryptographic hash algorithms from string",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Hash string to analyze",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="hash",
            subcommand="identify",
            handler=handle_crypto_hash_id,
            description="Identify cryptographic hash algorithms from string",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Hash string to analyze",
                ),
            ],
        )
    )

    # 4. Encoding
    registry.register_command(
        CommandDef(
            module="encoding",
            command="auto",
            handler=handle_encoding_auto,
            description="Recursive layered multi-base and text encoding cracker",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Encoded string or file",
                ),
                CommandArg(
                    name="max_depth",
                    type=int,
                    default=10,
                    is_option=True,
                    description="Max recursion depth",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="encoding",
            command="decode",
            handler=handle_encoding_decode,
            description="Decode standard bases (hex, base64, base32, base58, base85, base91)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Encoded string or file",
                ),
                CommandArg(
                    name="format",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-f",
                    description="Base format",
                ),
            ],
        )
    )

    # 5. Stego
    registry.register_command(
        CommandDef(
            module="stego",
            command="lsb",
            handler=handle_stego_lsb,
            description="Least Significant Bit (LSB) steganography extraction and brute-force",
            is_long_running=True,
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PNG carrier image",
                ),
                CommandArg(
                    name="order",
                    type=str,
                    default="RGB",
                    is_option=True,
                    description="Channel order",
                ),
                CommandArg(
                    name="bits",
                    type=int,
                    default=1,
                    is_option=True,
                    description="Number of bits per channel",
                ),
                CommandArg(
                    name="brute",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    description="Brute-force all combinations",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="png-chunks",
            handler=handle_stego_png_chunks,
            description="Parse and inspect PNG chunk structure and metadata",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PNG image",
                ),
            ],
        )
    )

    # 6. Forensic
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip-inspect",
            handler=handle_forensic_zip_inspect,
            description="Inspect ZIP archive headers, comments, and encryption",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="tar-inspect",
            handler=handle_forensic_tar_inspect,
            description="Inspect TAR archive headers and entries",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="TAR archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="archive-inspect",
            handler=handle_forensic_archive_inspect,
            description="Universal archive inspector (ZIP, TAR, GZ, BZ2, XZ, 7Z)",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Archive file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="carve",
            handler=handle_forensic_carve,
            description="Carve embedded files by signature magic",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Carve target file",
                ),
                CommandArg(
                    name="types",
                    type=str,
                    default="all",
                    is_option=True,
                    description="File types comma-separated",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="disk-inspect",
            handler=handle_forensic_disk_inspect,
            description="Inspect disk partition tables (MBR/GPT) and filesystems",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Disk image file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="timestamp",
            handler=handle_forensic_timestamp,
            description="Parse and convert timestamps across formats",
            args=[
                CommandArg(
                    name="value",
                    type=str,
                    default=None,
                    required=False,
                    description="Timestamp value",
                ),
                CommandArg(
                    name="format",
                    type=str,
                    default="auto",
                    is_option=True,
                    description="Input format",
                ),
            ],
        )
    )

    # 7. Reverse
    registry.register_command(
        CommandDef(
            module="reverse",
            command="disasm",
            handler=handle_reverse_disasm,
            description="Disassemble binary machine code",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file or hex",
                ),
                CommandArg(
                    name="arch",
                    type=str,
                    default="x86_64",
                    is_option=True,
                    short_flag="-a",
                    description="Architecture",
                ),
                CommandArg(
                    name="base",
                    type=str,
                    default="0x1000",
                    is_option=True,
                    description="Base address",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="reverse",
            command="cfg",
            handler=handle_reverse_cfg,
            description="Construct and display Control Flow Graph (CFG)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file",
                ),
                CommandArg(
                    name="arch",
                    type=str,
                    default="x86_64",
                    is_option=True,
                    short_flag="-a",
                    description="Architecture",
                ),
                CommandArg(
                    name="base",
                    type=str,
                    default="0x1000",
                    is_option=True,
                    description="Base address",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="reverse",
            command="nop",
            handler=handle_reverse_nop,
            description="Patch byte region with NOP instructions",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file to patch",
                ),
                CommandArg(
                    name="offset",
                    type=str,
                    default="0x0",
                    is_option=True,
                    description="Offset in hex or int",
                ),
                CommandArg(
                    name="length",
                    type=int,
                    default=1,
                    is_option=True,
                    description="Number of bytes to NOP",
                ),
                CommandArg(
                    name="arch",
                    type=str,
                    default="x86",
                    is_option=True,
                    description="Target architecture",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="reverse",
            command="patch",
            handler=handle_reverse_patch,
            description="Patch byte region with arbitrary bytes or NOP instructions",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file to patch",
                ),
                CommandArg(
                    name="offset",
                    type=str,
                    default="0x0",
                    is_option=True,
                    short_flag="-o",
                    description="Offset in hex or int",
                ),
                CommandArg(
                    name="replacement",
                    type=str,
                    default=None,
                    is_option=True,
                    description="Hex bytes to patch",
                ),
                CommandArg(
                    name="bytes",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-b",
                    description="Hex bytes to patch",
                ),
                CommandArg(
                    name="nop",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    description="NOP fill region",
                ),
                CommandArg(
                    name="length",
                    type=int,
                    default=1,
                    is_option=True,
                    short_flag="-l",
                    description="Number of bytes to NOP",
                ),
                CommandArg(
                    name="arch",
                    type=str,
                    default="x86",
                    is_option=True,
                    short_flag="-a",
                    description="Target architecture",
                ),
            ],
        )
    )

    # 8. PCAP
    registry.register_command(
        CommandDef(
            module="pcap",
            command="summary",
            handler=handle_pcap_summary,
            description="Summary statistics and protocol breakdown of PCAP/PCAPNG capture",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PCAP/PCAPNG capture file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="pcap",
            command="flows",
            handler=handle_pcap_flows,
            description="Extract and reconstruct network conversations and flows",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PCAP file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="pcap",
            command="dns",
            handler=handle_pcap_dns,
            description="Extract DNS queries and resolutions from capture",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PCAP file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="pcap",
            command="credentials",
            handler=handle_pcap_credentials,
            description="Extract cleartext credentials (HTTP, FTP, POP3, SMTP, IMAP)",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PCAP file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="pcap",
            command="http",
            handler=handle_pcap_http,
            description="Reconstruct HTTP requests and responses from capture",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PCAP file",
                ),
            ],
        )
    )

    # 9. Network
    registry.register_command(
        CommandDef(
            module="network",
            command="scan",
            handler=handle_network_scan,
            description="TCP port scanner and service banner grabber",
            is_long_running=True,
            args=[
                CommandArg(
                    name="host",
                    type=str,
                    default="127.0.0.1",
                    required=False,
                    description="Target host or IP",
                ),
                CommandArg(
                    name="ports",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-p",
                    description="Port range e.g. 80,443,1-1024",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=0.5,
                    is_option=True,
                    short_flag="-t",
                    description="Socket timeout",
                ),
                CommandArg(
                    name="workers",
                    type=int,
                    default=20,
                    is_option=True,
                    short_flag="-w",
                    description="Concurrent workers",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="network",
            command="banner",
            handler=handle_network_banner,
            description="Grab service banner from network socket",
            args=[
                CommandArg(
                    name="host",
                    type=str,
                    default="127.0.0.1",
                    required=False,
                    description="Target host",
                ),
                CommandArg(
                    name="port",
                    type=int,
                    default=80,
                    is_option=True,
                    short_flag="-p",
                    description="Port number",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=2.0,
                    is_option=True,
                    short_flag="-t",
                    description="Timeout",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="network",
            command="tls",
            handler=handle_network_tls,
            description="Inspect remote TLS/SSL certificate and cipher suite",
            args=[
                CommandArg(
                    name="host",
                    type=str,
                    default="localhost",
                    required=False,
                    description="Target host",
                ),
                CommandArg(
                    name="port",
                    type=int,
                    default=443,
                    is_option=True,
                    short_flag="-p",
                    description="TLS port",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=3.0,
                    is_option=True,
                    short_flag="-t",
                    description="Timeout",
                ),
            ],
        )
    )

    # 10. Web
    registry.register_command(
        CommandDef(
            module="web",
            command="headers",
            handler=handle_web_audit_headers,
            description="Audit HTTP security headers against OWASP standards",
            args=[
                CommandArg(
                    name="url",
                    type=str,
                    default="http://localhost",
                    required=False,
                    description="Target URL",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=5.0,
                    is_option=True,
                    short_flag="-t",
                    description="Timeout",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="web",
            command="audit-headers",
            handler=handle_web_audit_headers,
            description="Audit HTTP security headers against OWASP standards",
            args=[
                CommandArg(
                    name="url",
                    type=str,
                    default="http://localhost",
                    required=False,
                    description="Target URL",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=5.0,
                    is_option=True,
                    short_flag="-t",
                    description="Timeout",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="web",
            command="fuzz",
            handler=handle_web_fuzz,
            description="Concurrently probe endpoints and directories against base URL",
            args=[
                CommandArg(
                    name="url",
                    type=str,
                    default="http://localhost",
                    required=False,
                    description="Base URL",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-w",
                    is_path=True,
                    description="Wordlist path",
                ),
                CommandArg(
                    name="status",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-s",
                    description="Comma-separated status codes",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="web",
            command="extract",
            handler=handle_web_extract,
            description="Extract comments, links, scripts, and endpoints from HTML",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=False,
                    is_path=True,
                    description="HTML file or URL",
                ),
            ],
        )
    )

    # 11. OSINT
    registry.register_command(
        CommandDef(
            module="osint",
            command="dns",
            handler=handle_osint_dns,
            description="DNS records lookup (A, AAAA, MX, NS, TXT, SOA)",
            args=[
                CommandArg(
                    name="domain",
                    type=str,
                    default="example.com",
                    required=False,
                    description="Target domain",
                ),
                CommandArg(
                    name="types",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-t",
                    description="Record types comma-separated",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="osint",
            command="whois",
            handler=handle_osint_whois,
            description="Perform WHOIS domain registration lookup",
            args=[
                CommandArg(
                    name="domain",
                    type=str,
                    default="example.com",
                    required=False,
                    description="Target domain",
                ),
                CommandArg(
                    name="timeout",
                    type=float,
                    default=5.0,
                    is_option=True,
                    short_flag="-t",
                    description="Timeout",
                ),
            ],
        )
    )

    # 12. Password
    registry.register_command(
        CommandDef(
            module="password",
            command="mutate",
            handler=handle_password_mutate,
            description="Generate mutation candidates using John/Hashcat style rules",
            args=[
                CommandArg(
                    name="word", type=str, default="", required=False, description="Base word"
                ),
                CommandArg(
                    name="leet",
                    type=bool,
                    default=True,
                    is_option=True,
                    is_flag=True,
                    description="Apply leetspeak rules",
                ),
                CommandArg(
                    name="casing",
                    type=bool,
                    default=True,
                    is_option=True,
                    is_flag=True,
                    description="Apply capitalization rules",
                ),
                CommandArg(
                    name="affixes",
                    type=bool,
                    default=True,
                    is_option=True,
                    is_flag=True,
                    description="Apply common prefixes/suffixes",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="password",
            command="generate",
            handler=handle_password_generate,
            description="Combine wordlists and patterns into candidate list",
            args=[
                CommandArg(
                    name="words",
                    type=str,
                    default="",
                    is_option=True,
                    description="Base words comma-separated",
                ),
                CommandArg(
                    name="suffixes",
                    type=str,
                    default="!,123,2024",
                    is_option=True,
                    description="Suffixes comma-separated",
                ),
                CommandArg(
                    name="delimiter",
                    type=str,
                    default="",
                    is_option=True,
                    description="Delimiter between tokens",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="password",
            command="crack",
            handler=handle_password_crack,
            description="Dictionary and rule-based cryptographic hash cracker",
            is_long_running=True,
            args=[
                CommandArg(
                    name="target_hash",
                    type=str,
                    default="",
                    required=False,
                    description="Target hash to crack",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default="",
                    is_option=True,
                    is_path=True,
                    description="Wordlist path",
                ),
                CommandArg(
                    name="algo",
                    type=str,
                    default="auto",
                    is_option=True,
                    short_flag="-a",
                    description="Hash algorithm",
                ),
                CommandArg(
                    name="mutate",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-m",
                    description="Enable rule-based mutation",
                ),
            ],
        )
    )

    # 13. Additional Crypto
    registry.register_command(
        CommandDef(
            module="crypto",
            command="affine",
            handler=handle_crypto_affine,
            description="Affine cipher encryption, decryption, and brute-force",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Ciphertext or plaintext",
                ),
                CommandArg(
                    name="a",
                    type=int,
                    default=1,
                    is_option=True,
                    description="Multiplier (coprime with 26)",
                ),
                CommandArg(
                    name="b", type=int, default=0, is_option=True, description="Shift offset"
                ),
                CommandArg(
                    name="brute",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-b",
                    description="Brute-force all valid (a, b) pairs",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt instead of decrypt",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="enigma",
            handler=handle_crypto_enigma,
            description="Enigma M3 / M4 cipher simulator",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to encode/decode",
                ),
                CommandArg(
                    name="rotors",
                    type=str,
                    default="I II III",
                    is_option=True,
                    description="Rotor selection",
                ),
                CommandArg(
                    name="reflector",
                    type=str,
                    default="UKW-B",
                    is_option=True,
                    description="Reflector model",
                ),
                CommandArg(
                    name="rings",
                    type=str,
                    default="0 0 0",
                    is_option=True,
                    description="Ring settings",
                ),
                CommandArg(
                    name="positions",
                    type=str,
                    default="A A A",
                    is_option=True,
                    description="Rotor start positions",
                ),
                CommandArg(
                    name="plugboard",
                    type=str,
                    default="",
                    is_option=True,
                    description="Plugboard pairings",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="symboltable",
            handler=handle_crypto_symboltable,
            description="Encode or decode using CTF symbol tables",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=False,
                    description="Text or symbol sequence",
                ),
                CommandArg(
                    name="table",
                    type=str,
                    default="morse",
                    is_option=True,
                    short_flag="-t",
                    description="Table name",
                ),
                CommandArg(
                    name="encode",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encode instead of decode",
                ),
                CommandArg(
                    name="list_tables",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-l",
                    description="List available symbol tables",
                ),
            ],
        )
    )

    # 14. Additional Encoding
    registry.register_command(
        CommandDef(
            module="encoding",
            command="morse",
            handler=handle_encoding_morse,
            description="Encode or decode International Morse Code",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text or morse string",
                ),
                CommandArg(
                    name="encode",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encode instead of decode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="encoding",
            command="esolang",
            handler=handle_encoding_esolang,
            description="Interpret esoteric programming languages (Brainfuck, Ook, Deadfish, etc.)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Esolang source code",
                ),
                CommandArg(
                    name="lang",
                    type=str,
                    default="brainfuck",
                    is_option=True,
                    short_flag="-l",
                    description="Language: brainfuck, ook, deadfish, whitespace, lolcode, jsfuck",
                ),
            ],
        )
    )

    # 15. Additional Binary
    registry.register_command(
        CommandDef(
            module="binary",
            command="pe",
            handler=handle_binary_pe,
            description="Parse Windows PE executable headers, imports, sections",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PE binary file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="binary",
            command="macho",
            handler=handle_binary_macho,
            description="Parse macOS Mach-O headers, load commands, sections",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Mach-O binary file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="binary",
            command="packer",
            handler=handle_binary_packer,
            description="Detect binary packers and protectors (UPX, etc.)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Binary file",
                ),
            ],
        )
    )

    # 16. Additional Stego
    registry.register_command(
        CommandDef(
            module="stego",
            command="spectrogram",
            handler=handle_stego_spectrogram,
            description="Generate ASCII audio spectrogram to reveal hidden visual messages",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="morse-audio",
            handler=handle_stego_morse_audio,
            description="Detect and decode Morse code audio tones in WAV",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
                CommandArg(
                    name="threshold",
                    type=float,
                    default=None,
                    is_option=True,
                    description="Amplitude threshold",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text-null",
            handler=handle_stego_text_null,
            description="Extract null ciphers and acrostics from text",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Cover text"
                ),
                CommandArg(
                    name="mode",
                    type=str,
                    default="first-letter",
                    is_option=True,
                    short_flag="-m",
                    choices=["first-letter", "nth-letter", "first-sentence", "acrostic"],
                    description="Extraction mode",
                ),
                CommandArg(
                    name="n", type=int, default=2, is_option=True, description="Step for nth-letter"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text",
            subcommand="null",
            handler=handle_stego_text_null,
            description="Extract null ciphers and acrostics from text",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Cover text"
                ),
                CommandArg(
                    name="mode",
                    type=str,
                    default="first-letter",
                    is_option=True,
                    short_flag="-m",
                    choices=["first-letter", "nth-letter", "first-sentence", "acrostic"],
                    description="Extraction mode",
                ),
                CommandArg(
                    name="n", type=int, default=2, is_option=True, description="Step for nth-letter"
                ),
            ],
        )
    )

    # 17. Expanded Crypto Suite
    registry.register_command(
        CommandDef(
            module="crypto",
            command="substitution",
            handler=handle_crypto_substitution,
            description="Monoalphabetic substitution cipher solver via quadgram hill climbing",
            is_long_running=True,
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Ciphertext"
                ),
                CommandArg(
                    name="iterations",
                    type=int,
                    default=5000,
                    is_option=True,
                    short_flag="-i",
                    description="Iterations per restart",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="playfair",
            handler=handle_crypto_playfair,
            description="Playfair digraph cipher encryption, decryption, and simulated annealing",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-k",
                    description="5x5 matrix keyword",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
                CommandArg(
                    name="solve",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    description="Solve without key",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="railfence",
            handler=handle_crypto_railfence,
            description="Rail fence (zigzag) transposition cipher solver",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="rails",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-r",
                    description="Number of rails",
                ),
                CommandArg(
                    name="brute",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-b",
                    description="Brute-force rails",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="columnar",
            handler=handle_crypto_columnar,
            description="Columnar transposition cipher encryption and decryption",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-k",
                    description="Columnar permutation key",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="beaufort",
            handler=handle_crypto_beaufort,
            description="Beaufort and Variant Beaufort cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-k",
                    description="Alphabetic key",
                ),
                CommandArg(
                    name="variant",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    description="Use Variant Beaufort",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="autokey",
            handler=handle_crypto_autokey,
            description="Autokey polyalphabetic cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-k",
                    description="Initial key primer",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="adfgvx",
            handler=handle_crypto_adfgvx,
            description="ADFGVX fractionated transposition cipher",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text to process",
                ),
                CommandArg(
                    name="square_key",
                    type=str,
                    default="GERMAN",
                    is_option=True,
                    description="6x6 Polybius square keyword",
                ),
                CommandArg(
                    name="columnar_key",
                    type=str,
                    default="KAISER",
                    is_option=True,
                    description="Columnar transposition keyword",
                ),
                CommandArg(
                    name="encrypt",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-e",
                    description="Encrypt mode",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor",
            subcommand="repeating",
            handler=handle_crypto_xor_repeating,
            description="Break repeating-key XOR via Hamming distance key length estimation",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Ciphertext"
                ),
                CommandArg(
                    name="key_length",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-l",
                    description="Known key length",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor-repeating",
            handler=handle_crypto_xor_repeating,
            description="Break repeating-key XOR via Hamming distance key length estimation",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Ciphertext"
                ),
                CommandArg(
                    name="key_length",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-l",
                    description="Known key length",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor",
            subcommand="crib",
            handler=handle_crypto_xor_crib,
            description="Crib dragging across two two-time-pad XOR ciphertexts",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Ciphertext 1"
                ),
                CommandArg(
                    name="crib",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-c",
                    description="Known plaintext crib",
                ),
                CommandArg(
                    name="target_file",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-t",
                    description="Ciphertext 2",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="xor-crib",
            handler=handle_crypto_xor_crib,
            description="Crib dragging across two two-time-pad XOR ciphertexts",
            args=[
                CommandArg(
                    name="source", type=str, default=None, required=True, description="Ciphertext 1"
                ),
                CommandArg(
                    name="crib",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-c",
                    description="Known plaintext crib",
                ),
                CommandArg(
                    name="target_file",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-t",
                    description="Ciphertext 2",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="hash",
            subcommand="compute",
            handler=handle_crypto_hash_compute,
            description="Compute cryptographic hashes of input data",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Input data or file",
                ),
                CommandArg(
                    name="algo",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-a",
                    description="Algorithm name (md5, sha1, sha256, etc.)",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="hash",
            handler=handle_crypto_hash_compute,
            description="Compute cryptographic hashes of input data",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Input data or file",
                ),
                CommandArg(
                    name="algo",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-a",
                    description="Algorithm name",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="hash",
            subcommand="extend",
            handler=handle_crypto_hash_extend,
            description="Merkle-Damgard length extension attack (sha1 or sha256)",
            args=[
                CommandArg(
                    name="orig_hash",
                    type=str,
                    default="",
                    is_option=True,
                    description="Original known hash",
                ),
                CommandArg(
                    name="key_length",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-l",
                    description="Secret key length in bytes",
                ),
                CommandArg(
                    name="append",
                    type=str,
                    default="",
                    is_option=True,
                    description="Data string to append",
                ),
                CommandArg(
                    name="algo",
                    type=str,
                    default="sha256",
                    is_option=True,
                    short_flag="-a",
                    description="sha1 or sha256",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="length-ext",
            handler=handle_crypto_hash_extend,
            description="Merkle-Damgard length extension attack",
            args=[
                CommandArg(
                    name="orig_hash",
                    type=str,
                    default="",
                    is_option=True,
                    description="Original known hash",
                ),
                CommandArg(
                    name="key_length",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-l",
                    description="Secret key length in bytes",
                ),
                CommandArg(
                    name="append",
                    type=str,
                    default="",
                    is_option=True,
                    description="Data string to append",
                ),
                CommandArg(
                    name="algo",
                    type=str,
                    default="sha256",
                    is_option=True,
                    short_flag="-a",
                    description="sha1 or sha256",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="dlog",
            handler=handle_crypto_dlog,
            description="Solve discrete log g^x = h mod p via Pohlig-Hellman",
            args=[
                CommandArg(
                    name="g", type=int, default=0, is_option=True, description="Base generator g"
                ),
                CommandArg(name="h", type=int, default=0, is_option=True, description="Result h"),
                CommandArg(
                    name="p", type=int, default=0, is_option=True, description="Modulus prime p"
                ),
                CommandArg(
                    name="order", type=int, default=None, is_option=True, description="Group order"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="gcd",
            handler=handle_crypto_math_gcd,
            description="Greatest Common Divisor of two integers",
            args=[
                CommandArg(
                    name="a", type=int, default=0, required=True, description="First integer"
                ),
                CommandArg(
                    name="b", type=int, default=0, required=True, description="Second integer"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="modinv",
            handler=handle_crypto_math_modinv,
            description="Modular multiplicative inverse: a^-1 mod m",
            args=[
                CommandArg(name="a", type=int, default=0, required=True, description="Integer a"),
                CommandArg(name="m", type=int, default=0, required=True, description="Modulus m"),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="crt",
            handler=handle_crypto_math_crt,
            description="Chinese Remainder Theorem solver",
            args=[
                CommandArg(
                    name="remainders",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-r",
                    description="Comma-separated remainders",
                ),
                CommandArg(
                    name="moduli",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-m",
                    description="Comma-separated moduli",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="isprime",
            handler=handle_crypto_math_isprime,
            description="Miller-Rabin primality test",
            args=[
                CommandArg(
                    name="n", type=int, default=0, required=True, description="Number to test"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="factor",
            handler=handle_crypto_math_factor,
            description="Prime factorization via trial division and Pollard's rho",
            args=[
                CommandArg(
                    name="n", type=int, default=0, required=True, description="Composite integer"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="math",
            subcommand="totient",
            handler=handle_crypto_math_totient,
            description="Euler's totient phi(n)",
            args=[
                CommandArg(name="n", type=int, default=0, required=True, description="Integer n"),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="rsa",
            subcommand="factor",
            handler=handle_crypto_rsa_factor,
            description="Factor RSA modulus via small primes, Fermat, and Pollard's rho",
            args=[
                CommandArg(
                    name="n", type=int, default=0, required=True, description="RSA modulus n"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="rsa",
            subcommand="wiener",
            handler=handle_crypto_rsa_wiener,
            description="Wiener's continuous fraction attack for small private exponent d",
            args=[
                CommandArg(
                    name="modulus",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-n",
                    description="Modulus n",
                ),
                CommandArg(
                    name="exponent",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-e",
                    description="Public exponent e",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="rsa",
            subcommand="common-mod",
            handler=handle_crypto_rsa_common_mod,
            description="Common modulus attack on two ciphertexts under coprime exponents",
            args=[
                CommandArg(
                    name="modulus",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-n",
                    description="Common modulus n",
                ),
                CommandArg(
                    name="e1", type=int, default=0, is_option=True, description="Exponent 1"
                ),
                CommandArg(
                    name="e2", type=int, default=0, is_option=True, description="Exponent 2"
                ),
                CommandArg(
                    name="c1", type=int, default=0, is_option=True, description="Ciphertext 1"
                ),
                CommandArg(
                    name="c2", type=int, default=0, is_option=True, description="Ciphertext 2"
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="rsa",
            subcommand="common-factor",
            handler=handle_crypto_rsa_common_factor,
            description="Common factor attack on two RSA moduli sharing a prime factor",
            args=[
                CommandArg(
                    name="n1",
                    type=int,
                    default=0,
                    required=True,
                    is_option=True,
                    description="First modulus",
                ),
                CommandArg(
                    name="n2",
                    type=int,
                    default=0,
                    required=True,
                    is_option=True,
                    description="Second modulus",
                ),
                CommandArg(
                    name="ciphertext",
                    type=int,
                    default=None,
                    is_option=True,
                    short_flag="-c",
                    description="Ciphertext under n1",
                ),
                CommandArg(
                    name="exponent",
                    type=int,
                    default=65537,
                    is_option=True,
                    short_flag="-e",
                    description="Public exponent",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="rsa",
            subcommand="audit",
            handler=handle_crypto_rsa_audit,
            description="Automated RSA attack suite (small e, Wiener, Fermat, trial)",
            args=[
                CommandArg(
                    name="modulus",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-n",
                    description="Modulus n",
                ),
                CommandArg(
                    name="exponent",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-e",
                    description="Exponent e",
                ),
                CommandArg(
                    name="ciphertext",
                    type=int,
                    default=0,
                    is_option=True,
                    short_flag="-c",
                    description="Ciphertext c",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="ecc",
            subcommand="audit",
            handler=handle_crypto_ecc_audit,
            description="Inspect elliptic curve parameters and security properties",
            args=[
                CommandArg(
                    name="curve",
                    type=str,
                    default="secp256k1",
                    is_option=True,
                    short_flag="-c",
                    description="Named curve",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="jwt",
            subcommand="decode",
            handler=handle_crypto_jwt_decode,
            description="Decode and inspect JSON Web Token",
            args=[
                CommandArg(
                    name="token", type=str, default="", required=True, description="JWT string"
                ),
                CommandArg(
                    name="verify",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    description="Verify signature",
                ),
                CommandArg(
                    name="key",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-k",
                    description="HMAC secret key",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="jwt",
            subcommand="none",
            handler=handle_crypto_jwt_none,
            description="Forge JWT with 'none' algorithm vulnerability",
            args=[
                CommandArg(
                    name="token", type=str, default="", required=True, description="Original JWT"
                ),
                CommandArg(
                    name="alg",
                    type=str,
                    default="none",
                    is_option=True,
                    description="Algorithm casing (none, None, NONE)",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="crypto",
            command="pqc",
            subcommand="hardness",
            handler=handle_crypto_pqc_hardness,
            description="Estimate Learning With Errors (LWE) lattice security hardness",
            args=[
                CommandArg(
                    name="n",
                    type=int,
                    default=256,
                    is_option=True,
                    description="Lattice dimension n",
                ),
                CommandArg(
                    name="q", type=int, default=3329, is_option=True, description="Modulus q"
                ),
                CommandArg(
                    name="sigma",
                    type=float,
                    default=1.0,
                    is_option=True,
                    description="Error standard deviation",
                ),
            ],
        )
    )

    # 18. Expanded Stego Suite
    registry.register_command(
        CommandDef(
            module="stego",
            command="png",
            handler=handle_stego_png_chunks,
            description="Inspect PNG chunks, metadata, and trailing data",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="PNG image",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="jpeg",
            handler=handle_stego_jpeg,
            description="Inspect JPEG markers, comments, and trailing data",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="JPEG image",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="exif",
            handler=handle_stego_exif,
            description="Extract EXIF/TIFF metadata (Camera, GPS, Software) from images",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Image file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="channels",
            handler=handle_stego_channels,
            description="Analyze color channel bit planes for steganographic anomalies",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Image file",
                ),
                CommandArg(
                    name="channels",
                    type=int,
                    default=3,
                    is_option=True,
                    short_flag="-c",
                    description="Channel count (3=RGB, 4=RGBA)",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="steghide",
            handler=handle_stego_steghide,
            description="Steghide carrier inspection, extraction, and Stegseek cracking",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Carrier file",
                ),
                CommandArg(
                    name="passphrase",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-p",
                    description="Extraction passphrase",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-w",
                    is_path=True,
                    description="Wordlist to crack",
                ),
                CommandArg(
                    name="extract",
                    type=bool,
                    default=False,
                    is_option=True,
                    is_flag=True,
                    short_flag="-x",
                    description="Extract payload",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text",
            subcommand="acrostic",
            handler=handle_stego_text_acrostic,
            description="Extract acrostic letters (first character of each line)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text string or file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text-acrostic",
            handler=handle_stego_text_acrostic,
            description="Extract acrostic letters (first character of each line)",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text string or file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text",
            subcommand="reverse",
            handler=handle_stego_text_reverse,
            description="Detect and decode reversed and upside-down text",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text string or file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="text-reverse",
            handler=handle_stego_text_reverse,
            description="Detect and decode reversed and upside-down text",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Text string or file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="audio",
            subcommand="info",
            handler=handle_stego_audio_info,
            description="Parse WAV headers and extract RIFF metadata",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="wav-info",
            handler=handle_stego_audio_info,
            description="Parse WAV headers and extract RIFF metadata",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="audio",
            subcommand="morse",
            handler=handle_stego_morse_audio,
            description="Detect and decode Morse code audio tones from WAV",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
                CommandArg(
                    name="threshold",
                    type=float,
                    default=None,
                    is_option=True,
                    description="Amplitude threshold",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="stego",
            command="audio",
            subcommand="spectrogram",
            handler=handle_stego_spectrogram,
            description="Generate ASCII audio spectrogram to reveal hidden visual messages",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="WAV audio file",
                ),
            ],
        )
    )

    # 19. Expanded Forensic Suite
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip",
            subcommand="inspect",
            handler=handle_forensic_zip_inspect,
            description="Inspect ZIP archive headers, comments, and encryption",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip",
            subcommand="comments",
            handler=handle_forensic_zip_comments,
            description="Extract ZIP archive comments and per-file comments",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip-comments",
            handler=handle_forensic_zip_comments,
            description="Extract ZIP archive comments and per-file comments",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip",
            subcommand="crack",
            handler=handle_forensic_zip_crack,
            description="Dictionary attack on password-protected ZIP archives",
            is_long_running=True,
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-w",
                    is_path=True,
                    description="Path to dictionary wordlist",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="zip-crack",
            handler=handle_forensic_zip_crack,
            description="Dictionary attack on password-protected ZIP archives",
            is_long_running=True,
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="ZIP archive",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default="",
                    is_option=True,
                    short_flag="-w",
                    is_path=True,
                    description="Path to dictionary wordlist",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="tar",
            subcommand="inspect",
            handler=handle_forensic_tar_inspect,
            description="Inspect TAR archive headers and entries",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="TAR archive",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="archive",
            subcommand="inspect",
            handler=handle_forensic_archive_inspect,
            description="Universal archive inspector (ZIP, TAR, GZ, BZ2, XZ, 7Z)",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Archive file",
                ),
            ],
        )
    )
    registry.register_command(
        CommandDef(
            module="forensic",
            command="disk",
            subcommand="inspect",
            handler=handle_forensic_disk_inspect,
            description="Inspect disk partition tables (MBR/GPT) and filesystems",
            args=[
                CommandArg(
                    name="file",
                    type=str,
                    default=None,
                    required=True,
                    is_path=True,
                    description="Disk image file",
                ),
            ],
        )
    )

    # 20. Expanded OSINT Suite
    registry.register_command(
        CommandDef(
            module="osint",
            command="subdomains",
            handler=handle_osint_subdomains,
            description="Discover subdomains via Certificate Transparency logs (crt.sh) and DNS brute-force",
            args=[
                CommandArg(
                    name="domain",
                    type=str,
                    default="example.com",
                    required=True,
                    description="Target domain",
                ),
                CommandArg(
                    name="crt",
                    type=bool,
                    default=True,
                    is_option=True,
                    description="Use Certificate Transparency",
                ),
                CommandArg(
                    name="wordlist",
                    type=str,
                    default=None,
                    is_option=True,
                    short_flag="-w",
                    is_path=True,
                    description="Wordlist path",
                ),
                CommandArg(
                    name="workers",
                    type=int,
                    default=20,
                    is_option=True,
                    description="Concurrent threads",
                ),
            ],
        )
    )

    # 21. Expanded Encoding Suite
    registry.register_command(
        CommandDef(
            module="encoding",
            command="encode",
            handler=handle_encoding_encode,
            description="Encode data to base64, hex, base32, base58, base85, base91, url, html",
            args=[
                CommandArg(
                    name="source",
                    type=str,
                    default=None,
                    required=True,
                    description="Data or file to encode",
                ),
                CommandArg(
                    name="format",
                    type=str,
                    default="base64",
                    is_option=True,
                    short_flag="-f",
                    description="Encoding format",
                ),
            ],
        )
    )


# Automatically register on import
register_all_commands()
