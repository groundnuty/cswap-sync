import base64
import json

import pytest

from cswap_sync.store import DirStore, GitHubStore, StoreError, open_store


def test_dir_store_round_trip(tmp_path):
    s = DirStore(tmp_path)
    assert s.machines() == []
    s.write("vm1", b"a")
    s.write("laptop", b"b")
    (tmp_path / "machines" / "notes.txt").write_text("ignored")
    assert s.machines() == ["laptop", "vm1"]
    assert s.read("laptop") == b"b"


@pytest.mark.parametrize("name", ["../x", "a/b", "", ".hidden", "x" * 80])
def test_unsafe_machine_names_are_rejected(tmp_path, name):
    with pytest.raises(StoreError):
        DirStore(tmp_path).write(name, b"a")


def test_open_store_specs(tmp_path):
    assert isinstance(open_store(f"dir:{tmp_path}"), DirStore)
    assert isinstance(open_store("github:groundnuty/cswap-sync-store", "tok"), GitHubStore)
    for bad in ("github:nope", "s3:bucket", "dir:"):
        with pytest.raises(StoreError):
            open_store(bad, "tok")
    with pytest.raises(StoreError):
        open_store("github:o/r", None)


class FakeGitHub:
    def __init__(self):
        self.files = {}   # name -> (sha, bytes)
        self.calls = []
        self.stale_once = False

    def __call__(self, method, path, body=None, accept=""):
        self.calls.append((method, path))
        if method == "GET" and path == "machines":
            if not self.files:
                return 404, b'{"message": "Not Found"}'
            return 200, json.dumps([{"type": "file", "name": n, "sha": s}
                                    for n, (s, _) in self.files.items()]).encode()
        name = path.split("/", 1)[1]
        if method == "GET":
            return (200, self.files[name][1]) if name in self.files else (404, b"{}")
        if method == "PUT":
            have = self.files.get(name, (None, b""))[0]
            if self.stale_once or body.get("sha") != have:
                self.stale_once = False
                return 409, b'{"message": "sha mismatch"}'
            sha = f"sha{len(self.calls)}"
            self.files[name] = (sha, base64.b64decode(body["content"]))
            return 201, json.dumps({"content": {"sha": sha}}).encode()
        raise AssertionError(method)


def test_github_store_creates_updates_and_reads():
    gh = FakeGitHub()
    s = GitHubStore("o/r", "tok")
    s._request = gh
    assert s.machines() == []
    s.write("vm1", b"v1")
    s.write("vm1", b"v2")
    assert s.machines() == ["vm1"]
    assert s.read("vm1") == b"v2"


def test_github_store_retries_once_on_a_stale_sha():
    gh = FakeGitHub()
    s = GitHubStore("o/r", "tok")
    s._request = gh
    s.write("m", b"v1")
    gh.stale_once = True
    s.write("m", b"v2")
    assert s.read("m") == b"v2"


def test_github_errors_name_the_status_but_not_the_token():
    s = GitHubStore("o/r", "SECRET-TOKEN")
    s._request = lambda *a, **k: (401, b'{"message": "Bad credentials"}')
    with pytest.raises(StoreError) as e:
        s.machines()
    assert "401" in str(e.value) and "Bad credentials" in str(e.value)
    assert "SECRET-TOKEN" not in str(e.value)
