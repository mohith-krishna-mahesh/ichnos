"""Remote Oracle Secret Recovery Client.

Recovers unknown byte sequences from an HTTP oracle by probing byte guesses
per address position and identifying discriminating responses.
Supports persistent checkpoint resumption and concurrent worker threads.
Zero external dependencies (uses stdlib urllib.request).
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

DEFAULT_SECRET_LENGTH = 16
DEFAULT_BATCH_SIZE = 16
DEFAULT_PROGRAM_TEMPLATE = "0200{addr:02x}0101{guess:02x}05000106000300000007fd00"


class OracleClient:
    """HTTP JSON client for querying remote oracles with retries and authentication."""

    def __init__(
        self,
        url: str,
        token: str | None = None,
        retries: int = 3,
        timeout: float = 15.0,
        request_key: str = "programs",
        response_key: str = "results",
        submit_key: str = "key",
    ):
        self.url = url
        self.token = token
        self.retries = retries
        self.timeout = timeout
        self.request_key = request_key
        self.response_key = response_key
        self.submit_key = submit_key

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")

        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_body = resp.read().decode("utf-8")
                    return json.loads(resp_body)
            except Exception as exc:
                if attempt == self.retries - 1:
                    raise RuntimeError(f"Oracle query failed after {self.retries} attempts: {exc}") from exc
                time.sleep(2**attempt)
        raise RuntimeError("Unreachable")

    def query(self, programs: list[str]) -> list[Any]:
        """Queries the oracle with a batch of programs/guesses."""
        res = self._post({self.request_key: programs})
        if self.response_key not in res:
            raise KeyError(f"Expected key {self.response_key!r} not found in oracle response: {list(res.keys())}")
        return res[self.response_key]

    def submit(self, key_hex: str) -> dict[str, Any]:
        """Submits the recovered secret to the challenge endpoint."""
        return self._post({self.submit_key: key_hex})


def is_success(result: Any, success_value: str, success_key: str | None = None) -> bool:
    """Checks if an oracle response indicates a correct guess."""
    if success_key and isinstance(result, dict):
        val = result.get(success_key)
    else:
        val = result
    return str(val) == str(success_value)


class ResumeState:
    """Thread-safe checkpoint file {addr: value} for tracking recovered bytes."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[int, int] = {}
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.data = {int(k): int(v) for k, v in loaded.items()}
            except Exception:
                self.data = {}

    def get(self, addr: int) -> int | None:
        return self.data.get(addr)

    def set(self, addr: int, value: int) -> None:
        with self.lock:
            self.data[addr] = value
            if self.path:
                try:
                    with open(self.path, "w", encoding="utf-8") as f:
                        json.dump(self.data, f, indent=2)
                except OSError:
                    pass


def recover_byte(
    client: OracleClient,
    addr: int,
    batch_size: int,
    program_template: str,
    success_value: str,
    success_key: str | None = None,
    alphabet_size: int = 256,
) -> int:
    """Probes all byte values for a single address position."""
    for start in range(0, alphabet_size, batch_size):
        guesses = list(range(start, min(alphabet_size, start + batch_size)))
        programs = [program_template.format(addr=addr, guess=g) for g in guesses]
        results = client.query(programs)
        for guess, result in zip(guesses, results):
            if is_success(result, success_value, success_key):
                return guess
    raise RuntimeError(f"Could not recover byte at address {addr}")


@dataclass
class OracleRecoveryResult:
    """Represents the outcome of an oracle recovery run."""

    secret_bytes: bytes
    secret_hex: str
    recovered_count: int
    total_length: int
    submit_response: dict[str, Any] | None = None


def recover_secret(
    client: OracleClient,
    length: int = DEFAULT_SECRET_LENGTH,
    batch_size: int = DEFAULT_BATCH_SIZE,
    program_template: str = DEFAULT_PROGRAM_TEMPLATE,
    success_value: str = "HALTED",
    success_key: str | None = None,
    workers: int = 1,
    resume: ResumeState | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
    submit_on_finish: bool = False,
) -> OracleRecoveryResult:
    """Recovers full unknown secret using the oracle client.

    Args:
        client: OracleClient configured with target URL and parameters.
        length: Total secret length in bytes.
        batch_size: Number of guesses bundled per request.
        program_template: Format string with {addr} and {guess} placeholders.
        success_value: Response value indicating a correct guess.
        success_key: JSON key containing the response value.
        workers: Number of concurrent worker threads across byte positions.
        resume: Optional ResumeState checkpoint object.
        on_progress: Optional callback fn(addr, value, total_length).
        submit_on_finish: If True, submits secret using client.submit().

    Returns:
        OracleRecoveryResult with recovered bytes and hex representation.
    """
    state = resume or ResumeState(None)
    todo = [addr for addr in range(length) if state.get(addr) is None]

    def work(addr: int) -> tuple[int, int]:
        val = recover_byte(
            client=client,
            addr=addr,
            batch_size=batch_size,
            program_template=program_template,
            success_value=success_value,
            success_key=success_key,
        )
        state.set(addr, val)
        if on_progress:
            on_progress(addr, val, length)
        return addr, val

    if workers > 1 and todo:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(work, todo))
    else:
        for addr in todo:
            work(addr)

    recovered = bytes(state.data[addr] for addr in range(length))
    submit_res = None
    if submit_on_finish:
        submit_res = client.submit(recovered.hex())

    return OracleRecoveryResult(
        secret_bytes=recovered,
        secret_hex=recovered.hex(),
        recovered_count=len(state.data),
        total_length=length,
        submit_response=submit_res,
    )
