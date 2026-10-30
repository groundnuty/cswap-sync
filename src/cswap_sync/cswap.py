"""The cswap CLI, called as a subprocess.

Logins travel only through pipes: `cswap export -` into memory and
`cswap import -` from memory. Nothing in this module prints or logs them.
"""

from __future__ import annotations

import json
import subprocess


class CswapError(Exception):
    pass


def _tail(text: str) -> str:
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return lines[-1] if lines else "no output"


class Cswap:
    def __init__(self, binary: str = "cswap", env: dict | None = None, timeout: int = 180):
        self.binary = binary
        self.env = env
        self.timeout = timeout

    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self.binary, *args], input=stdin, capture_output=True,
                text=True, env=self.env, timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CswapError(f"cswap {args[0]}: {e}") from None

    def accounts(self) -> list[dict]:
        p = self._run("list", "--json")
        if p.returncode != 0:
            raise CswapError(f"cswap list failed: {_tail(p.stderr)}")
        return json.loads(p.stdout)["accounts"]

    def export(self, accounts: list[dict]) -> dict:
        """All stored logins. If the whole export fails (an active account
        whose live login was wiped makes it fail), export slot by slot."""
        p = self._run("export", "-")
        if p.returncode == 0:
            return json.loads(p.stdout)
        entries = []
        for a in accounts:
            q = self._run("export", "-", "--account", str(a["number"]))
            if q.returncode == 0:
                entries.extend(json.loads(q.stdout).get("accounts", []))
        return {"accounts": entries}

    def import_envelope(self, envelope: dict, force: bool = False) -> list[str]:
        args = ["import", "-"] + (["--force"] if force else [])
        p = self._run(*args, stdin=json.dumps(envelope))
        if p.returncode != 0:
            raise CswapError(f"cswap import failed: {_tail(p.stderr)}")
        return [ln.strip() for ln in p.stderr.splitlines() if ln.strip()]

    def activate(self, number: int) -> None:
        """Rewrite the live login from the slot's stored copy."""
        p = self._run("switch", str(number), "--force")
        if p.returncode != 0:
            raise CswapError(f"cswap switch {number} --force failed: {_tail(p.stderr)}")
