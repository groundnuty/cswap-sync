import json
import os
import stat
import sys
from pathlib import Path

import pytest
from conftest import ORG_A, login

from cswap_sync.cli import main

FAKE = Path(__file__).with_name("fake_cswap.py")
H = 3_600_000


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A config dir with a sync key, a dir store, and a fake cswap per machine."""
    store = tmp_path / "store"
    cdir_key = None

    def make(name, entries, statuses=None, active=None, export_fails=False):
        nonlocal cdir_key
        cdir = tmp_path / name
        if cdir_key is None:
            assert main(["keygen", "--config-dir", str(cdir)]) == 0
            cdir_key = (cdir / "key").read_text()
        else:
            cdir.mkdir()
            (cdir / "key").write_text(cdir_key)
            os.chmod(cdir / "key", 0o600)
        st = cdir / "cswap.json"
        st.write_text(json.dumps({"entries": entries, "statuses": statuses or {},
                                  "active": active, "export_fails": export_fails}))
        wrapper = cdir / "cswap"
        wrapper.write_text(f"#!/bin/sh\nFAKE_CSWAP_STATE={st} exec {sys.executable} {FAKE} \"$@\"\n")
        wrapper.chmod(0o755)
        (cdir / "config.json").write_text(json.dumps(
            {"store": f"dir:{store}", "machine": name, "cswap": str(wrapper)}))

        def cli(*args):
            return main([*args, "--config-dir", str(cdir)])

        cli.state = lambda: json.loads(st.read_text())
        cli.dir = cdir
        return cli

    return make


def test_keygen_writes_a_private_key_once(tmp_path, capsys):
    cdir = tmp_path / "c"
    assert main(["keygen", "--config-dir", str(cdir)]) == 0
    assert stat.S_IMODE((cdir / "key").stat().st_mode) == 0o600
    key = (cdir / "key").read_text()
    assert key.strip() not in capsys.readouterr().out
    assert main(["keygen", "--config-dir", str(cdir)]) == 1
    assert (cdir / "key").read_text() == key


def test_a_world_readable_key_is_refused(machine):
    vm = machine("vm1", [])
    os.chmod(vm.dir / "key", 0o644)
    with pytest.raises(SystemExit, match="chmod 600"):
        vm("status")


def test_end_to_end_status_then_run(machine, capsys):
    mac = machine("laptop", [login("a@x", ORG_A, "rt-good", 1016 * H, number=6)])
    vm = machine("vm1", [login("a@x", ORG_A, "rt-dead", 1000 * H, number=5)],
                 statuses={"5": "relogin_required"})
    assert mac("publish") == 0
    capsys.readouterr()

    assert vm("status") == 0
    out = capsys.readouterr().out
    assert "repair #5 a@x" in out and "from laptop" in out
    assert "rt-good" not in out and "rt-dead" not in out
    assert vm.state()["entries"][0]["credentials"]["claudeAiOauth"]["refreshToken"] == "rt-dead"

    assert vm("run") == 0
    out = capsys.readouterr().out
    assert "cswap: Replaced a@x" in out
    assert vm.state()["entries"][0]["credentials"]["claudeAiOauth"]["refreshToken"] == "rt-good"
    assert "rt-good" not in out


def test_a_failing_full_export_falls_back_to_slot_by_slot(machine, capsys):
    mac = machine("laptop", [login("a@x", ORG_A, "rt-good", 1016 * H)], export_fails=True)
    assert mac("publish") == 0
    calls = mac.state()["calls"]
    assert ["export", "-", "--account", "1"] in calls
    assert "published 1 working login" in capsys.readouterr().out
