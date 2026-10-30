"""The shared store: one encrypted file per machine, `machines/<name>.enc`.

`GitHubStore` uses a private repo through the contents API with a
fine-grained token scoped to that repo. `DirStore` is a plain directory, for
tests and for machines that share a filesystem.
"""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

PREFIX = "machines"
SUFFIX = ".enc"
MACHINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class StoreError(Exception):
    pass


def check_machine(name: str) -> str:
    if not MACHINE_RE.match(name):
        raise StoreError(f"invalid machine name: {name!r}")
    return name


def _machine_of(filename: str) -> str | None:
    if not filename.endswith(SUFFIX):
        return None
    name = filename[: -len(SUFFIX)]
    return name if MACHINE_RE.match(name) else None


def open_store(spec: str, token: str | None = None):
    kind, _, where = spec.partition(":")
    if kind == "dir" and where:
        return DirStore(where)
    if kind == "github" and re.match(r"^[\w.-]+/[\w.-]+$", where):
        if not token:
            raise StoreError("a github store needs a token (github-token file or CSWAP_SYNC_GITHUB_TOKEN)")
        return GitHubStore(where, token)
    raise StoreError(f"store must be github:OWNER/REPO or dir:PATH, got {spec!r}")


class DirStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser()
        self.dir = self.root / PREFIX

    def __str__(self) -> str:
        return f"dir:{self.root}"

    def machines(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(m for p in self.dir.iterdir() if (m := _machine_of(p.name)))

    def read(self, machine: str) -> bytes:
        return (self.dir / (check_machine(machine) + SUFFIX)).read_bytes()

    def write(self, machine: str, data: bytes) -> None:
        target = self.dir / (check_machine(machine) + SUFFIX)
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, target)


class GitHubStore:
    def __init__(self, repo: str, token: str, api: str = "https://api.github.com"):
        self.repo = repo
        self._token = token
        self._api = api
        self._shas: dict[str, str] = {}

    def __str__(self) -> str:
        return f"github:{self.repo}"

    def _request(self, method: str, path: str, body: dict | None = None,
                 accept: str = "application/vnd.github+json") -> tuple[int, bytes]:
        req = urllib.request.Request(
            f"{self._api}/repos/{self.repo}/contents/{path}",
            method=method,
            data=None if body is None else json.dumps(body).encode(),
        )
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "cswap-sync")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, TimeoutError) as e:
            raise StoreError(f"GitHub unreachable: {getattr(e, 'reason', e)}") from None

    @staticmethod
    def _why(status: int, body: bytes) -> str:
        try:
            return f"HTTP {status}: {json.loads(body).get('message', '')}"
        except (ValueError, AttributeError):
            return f"HTTP {status}"

    def machines(self) -> list[str]:
        status, body = self._request("GET", PREFIX)
        if status == 404:
            self._shas = {}
            return []
        if status != 200:
            raise StoreError(f"listing {self} failed, {self._why(status, body)}")
        self._shas = {
            m: item["sha"]
            for item in json.loads(body)
            if item.get("type") == "file" and (m := _machine_of(item.get("name", "")))
        }
        return sorted(self._shas)

    def read(self, machine: str) -> bytes:
        path = f"{PREFIX}/{check_machine(machine)}{SUFFIX}"
        status, body = self._request("GET", path, accept="application/vnd.github.raw+json")
        if status != 200:
            raise StoreError(f"reading {machine} from {self} failed, {self._why(status, body)}")
        return body

    def write(self, machine: str, data: bytes) -> None:
        path = f"{PREFIX}/{check_machine(machine)}{SUFFIX}"
        if machine not in self._shas:
            self.machines()
        for attempt in (1, 2):
            body = {"message": f"{machine}: publish", "content": base64.b64encode(data).decode()}
            if machine in self._shas:
                body["sha"] = self._shas[machine]
            status, resp = self._request("PUT", path, body)
            if status in (200, 201):
                self._shas[machine] = json.loads(resp)["content"]["sha"]
                return
            if status in (409, 422) and attempt == 1:
                self.machines()  # our cached sha was stale; refetch once
                continue
            raise StoreError(f"writing {machine} to {self} failed, {self._why(status, resp)}")
