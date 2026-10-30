import json

from conftest import ORG_A, ORG_B, FakeCswap, login

from cswap_sync.crypto import seal, unseal
from cswap_sync.store import DirStore
from cswap_sync.sync import run_pass

H = 3_600_000


def quiet(_msg):
    pass


def test_a_dead_login_heals_from_another_machine(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-good", 1016 * H, number=6)])
    vm = FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H, number=5)],
                   statuses={5: "relogin_required"})

    run_pass(mac, store, key, "laptop", {}, log=quiet)
    res = run_pass(vm, store, key, "vm1", {}, log=quiet)

    assert [a.kind for a in res.actions] == ["repair"]
    (env, force), = vm.imports
    assert force is False  # cswap's own dead-slot check decides
    assert vm.entries[0]["credentials"]["claudeAiOauth"]["refreshToken"] == "rt-good"
    assert vm.entries[0]["number"] == 5


def test_a_dead_machine_publishes_nothing_for_its_dead_login(tmp_path, key):
    store = DirStore(tmp_path)
    vm = FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H)], statuses={1: "relogin_required"})
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert json.loads(unseal(key, "vm1", store.read("vm1")))["accounts"] == []


def test_the_store_holds_no_plaintext(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-SECRET", 1016 * H)], api_keys=[5])
    run_pass(mac, store, key, "laptop", {}, log=quiet)
    raw = b"".join(p.read_bytes() for p in (tmp_path / "machines").iterdir())
    assert b"rt-SECRET" not in raw and b"a@x" not in raw and b"sk-ant" not in raw


def test_publishing_is_skipped_while_nothing_changed(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-1", 1016 * H)])
    state = {}
    assert run_pass(mac, store, key, "laptop", state, log=quiet).published
    assert not run_pass(mac, store, key, "laptop", state, log=quiet).published
    mac.entries[0]["credentials"]["claudeAiOauth"].update(refreshToken="rt-2", expiresAt=1024 * H)
    assert run_pass(mac, store, key, "laptop", state, log=quiet).published


def test_a_failed_copy_is_not_retried(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-good", 1016 * H)])
    run_pass(mac, store, key, "laptop", {}, log=quiet)

    vm = FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H)], statuses={1: "relogin_required"})
    state = {}
    run_pass(vm, store, key, "vm1", state, log=quiet)
    vm.statuses[1] = "relogin_required"  # the imported copy turned out dead too
    res = run_pass(vm, store, key, "vm1", state, log=quiet)
    assert res.actions == [] and len(vm.imports) == 1


def test_a_wiped_active_login_is_imported_with_force_and_reactivated(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-good", 1016 * H)])
    run_pass(mac, store, key, "laptop", {}, log=quiet)
    vm = FakeCswap([login("a@x", ORG_A, "rt-gone", 1000 * H, number=3)],
                   statuses={3: "no_credentials"}, active=3)
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert [f for _, f in vm.imports] == [True]
    assert vm.activated == [3]


def test_missing_logins_are_added(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-1", 1016 * H, number=1),
                     login("m@x", ORG_B, "rt-2", 1016 * H, number=7)])
    run_pass(mac, store, key, "laptop", {}, log=quiet)
    vm = FakeCswap([login("a@x", ORG_A, "rt-own", 1012 * H, number=1)])
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert sorted(e["email"] for e in vm.entries) == ["a@x", "m@x"]
    assert vm.entries[0]["credentials"]["claudeAiOauth"]["refreshToken"] == "rt-own"


def test_status_mode_changes_nothing(tmp_path, key):
    store = DirStore(tmp_path)
    mac = FakeCswap([login("a@x", ORG_A, "rt-good", 1016 * H)])
    run_pass(mac, store, key, "laptop", {}, log=quiet)
    vm = FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H)], statuses={1: "relogin_required"})
    state = {}
    res = run_pass(vm, store, key, "vm1", state, publish=False, apply=False, log=quiet)
    assert len(res.actions) == 1 and vm.imports == []
    assert store.machines() == ["laptop"] and "published" not in state


def test_unreadable_or_misnamed_blobs_are_skipped(tmp_path, key):
    store = DirStore(tmp_path)
    store.write("broken", b"garbage")
    store.write("liar", seal(key, "liar", json.dumps({"format": 1, "machine": "other",
                                                      "accounts": []}).encode()))
    vm = FakeCswap([login("a@x", ORG_A, "rt-1", 1000 * H)])
    res = run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert len(res.skipped) == 2 and res.actions == []
