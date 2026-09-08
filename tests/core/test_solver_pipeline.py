"""Unit tests for AutoSolver end-to-end pipeline across multiple CTF domains."""

import base64
import tempfile
import zipfile
from pathlib import Path

from ichnos.core.solver import AutoSolver

P = 91504757838363943504295625810220813967989474844339778893801137976004695306807
Q = 68153637887010023264406645865511423597382660425424362250152301727681392470611
R = 110413925358020719269592417955850500969137321350008250905077228929880941219911


def test_solver_directory_workspace():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        chall_py = p / "chall.py"
        chall_py.write_text(f"""
p = {P}
q = {Q}
r = {R}

N1 = p * q
N2 = q * r
e = 65537
""")
        out_txt = p / "output.txt"
        m = int.from_bytes(b"FLAG{folder_pipeline_solved}", "big")
        n1 = P * Q
        c1 = pow(m, 65537, n1)
        out_txt.write_text(f"c1 = {c1}\n")

        trace, result = AutoSolver.solve(targets=[p])

        assert trace.solved is True
        assert trace.flag == "FLAG{folder_pipeline_solved}"
        assert result.status == "success"


def test_solver_zip_archive():
    with tempfile.TemporaryDirectory() as td:
        zip_path = Path(td) / "challenge.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("notes.txt", "Check comments!")
            zf.comment = b"Look at this: FLAG{zip_comment_flag_extracted}"

        trace, result = AutoSolver.solve(targets=[zip_path])

        assert trace.solved is True
        assert trace.flag == "FLAG{zip_comment_flag_extracted}"


def test_solver_layered_encoding():
    # Layer 1: Hex
    # Layer 2: Base64
    inner = b"FLAG{layered_base_solved}".hex()
    encoded = base64.b64encode(inner.encode()).decode()

    trace, result = AutoSolver.solve(active_text=encoded)

    assert trace.solved is True
    assert trace.flag == "FLAG{layered_base_solved}"
    assert "Layered Decoding" in trace.attack_name


def test_solver_missing_path_not_treated_as_raw_text():
    trace, result = AutoSolver.solve(targets=["~/nonexistent_ctf_dir_12345/chall.py"])
    assert trace.solved is False
    assert result.status == "error"
    # Verify it reported path not found rather than ingesting path string as raw text
    assert any("Target path" in step.title for step in trace.steps)
    assert not any("Raw text target ingested" in step.title for step in trace.steps)


def test_solver_tilde_expansion(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        chall_py = p / "chall.py"
        chall_py.write_text(f"""
p = {P}
q = {Q}
r = {R}

N1 = p * q
N2 = q * r
e = 65537
""")
        out_txt = p / "output.txt"
        m = int.from_bytes(b"FLAG{tilde_solved}", "big")
        n1 = P * Q
        c1 = pow(m, 65537, n1)
        out_txt.write_text(f"c1 = {c1}\n")

        orig_expanduser = Path.expanduser

        def mock_expanduser(self):
            if str(self).startswith("~"):
                rel = str(self)[1:].lstrip("/\\")
                return p / rel if rel else p
            return orig_expanduser(self)

        monkeypatch.setattr(Path, "expanduser", mock_expanduser)

        trace, result = AutoSolver.solve(targets=["~/"])
        assert trace.solved is True
        assert trace.flag == "FLAG{tilde_solved}"


def test_handle_solve_with_directory():
    from ichnos.core.commands import handle_solve

    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        chall_py = p / "chall.py"
        chall_py.write_text(f"""
p = {P}
q = {Q}
r = {R}

N1 = p * q
N2 = q * r
e = 65537
""")
        out_txt = p / "output.txt"
        m = int.from_bytes(b"FLAG{handle_solve_dir}", "big")
        n1 = P * Q
        c1 = pow(m, 65537, n1)
        out_txt.write_text(f"c1 = {c1}\n")

        res = handle_solve(source=str(p))
        assert res.status == "success"
        assert any("FLAG{handle_solve_dir}" in c.decoded_str for c in res.candidates)

        # Multi-file string argument
        res_multi = handle_solve(source=f"{chall_py} {out_txt}")
        assert res_multi.status == "success"
        assert any("FLAG{handle_solve_dir}" in c.decoded_str for c in res_multi.candidates)


def test_solve_command_is_long_running():
    from ichnos.core.runner import CommandRunner

    cmd_def, _ = CommandRunner._resolve_command(["solve"])
    assert cmd_def is not None
    assert cmd_def.is_long_running is True


def test_large_vector_parameter_harvesting_bounded():
    import time

    from ichnos.core.harvester import CTFHarvester

    # Simulate a lattice/LWE public key with 200 large integers
    large_ints = [2**768 + i for i in range(200)]
    code = f"pk = (list(range(500)), {tuple(large_ints)})\nct = 12345\n"

    params = CTFHarvester.harvest_text(code, source_name="lwe_chall.py")
    # Must not have created hundreds of moduli
    assert len(params.moduli) <= 5
    # Total extracted variables must be bounded
    assert len(params.all_vars) < 50

    t0 = time.time()
    trace, result = AutoSolver.solve(active_text=code)
    elapsed = time.time() - t0
    # Must complete fast without hanging in RSA loops
    assert elapsed < 3.0
