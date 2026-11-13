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


SETTINGS = {"disabled": True, "threshold": 85.0, "alias": "pk"}


def _dead_vm(**kw):
    return FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H, number=8)],
                     statuses={8: kw.pop("status", "relogin_required")},
                     settings={8: dict(SETTINGS)}, **kw)


def _published(tmp_path, key):
    store = DirStore(tmp_path)
    run_pass(FakeCswap([login("a@x", ORG_A, "rt-good", 1016 * H, number=6)]),
             store, key, "laptop", {}, log=quiet)
    return store


def test_a_repaired_slot_keeps_what_the_user_set_on_it(tmp_path, key):
    store = _published(tmp_path, key)
    vm, logs = _dead_vm(), []
    run_pass(vm, store, key, "vm1", {}, log=logs.append)
    assert vm.entries[0]["credentials"]["claudeAiOauth"]["refreshToken"] == "rt-good"
    assert vm.settings[8] == SETTINGS
    assert any("kept #8 disabled=True" in m for m in logs)


def test_a_repaired_active_slot_keeps_its_settings_too(tmp_path, key):
    store = _published(tmp_path, key)
    vm = _dead_vm(status="no_credentials", active=8)
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert vm.activated == [8] and vm.settings[8] == SETTINGS


def test_only_settings_the_import_dropped_are_set_again(tmp_path, key):
    class KeepsAlias(FakeCswap):
        def import_envelope(self, envelope, force=False):
            alias = self.settings.get(8, {}).get("alias")
            out = super().import_envelope(envelope, force)
            self.settings.setdefault(8, {})["alias"] = alias
            return out

    store = _published(tmp_path, key)
    vm = KeepsAlias([login("a@x", ORG_A, "rt-dead", 1000 * H, number=8)],
                    statuses={8: "relogin_required"}, settings={8: dict(SETTINGS)})
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert sorted(name for _, name, _ in vm.set_calls) == ["disabled", "threshold"]
    assert vm.settings[8] == SETTINGS


def test_a_slot_without_settings_needs_no_extra_list(tmp_path, key):
    store = _published(tmp_path, key)
    vm = FakeCswap([login("a@x", ORG_A, "rt-dead", 1000 * H)], statuses={1: "relogin_required"})
    run_pass(vm, store, key, "vm1", {}, log=quiet)
    assert vm.list_calls == 1 and vm.set_calls == []
