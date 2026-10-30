from conftest import ORG_A, ORG_B, login, row

from cswap_sync import plan as P

H = 3_600_000
OLD, NEW, NEWER = 1_000 * H, 1_008 * H, 1_016 * H


def copy_(machine, entry, published="2026-10-30T08:00:00Z"):
    return P.Copy(machine, entry, published)


def test_a_dead_login_is_repaired_from_the_newest_working_copy():
    mine = login("a@x", ORG_A, "rt-dead", OLD, number=5)
    older = copy_("vm2", login("a@x", ORG_A, "rt-1", NEW, number=6))
    newest = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER, number=6))
    actions = P.plan([row(mine, "relogin_required")], {"accounts": [mine]}, [older, newest])
    assert [(a.kind, a.number, a.source.machine) for a in actions] == [("repair", 5, "laptop")]


def test_a_working_login_is_never_touched_even_by_a_newer_copy():
    mine = login("a@x", ORG_A, "rt-1", OLD)
    newer = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER))
    assert P.plan([row(mine, "ok")], {"accounts": [mine]}, [newer]) == []


def test_transient_states_are_left_to_cswap():
    mine = login("a@x", ORG_A, "rt-1", OLD)
    newer = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER))
    for status in ("token_expired", "unavailable", "foreign_credential", "keychain_unavailable"):
        assert P.plan([row(mine, status)], {"accounts": [mine]}, [newer]) == [], status


def test_the_same_generation_is_not_imported_again():
    mine = login("a@x", ORG_A, "rt-dead", OLD)
    same = copy_("laptop", login("a@x", ORG_A, "rt-dead", OLD))
    assert P.plan([row(mine, "relogin_required")], {"accounts": [mine]}, [same]) == []


def test_a_copy_already_tried_is_skipped_for_the_next_one():
    mine = login("a@x", ORG_A, "rt-dead", OLD)
    tried = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER))
    other = copy_("vm2", login("a@x", ORG_A, "rt-1", NEW))
    actions = P.plan([row(mine, "relogin_required")], {"accounts": [mine]}, [tried, other],
                     tried={"a@x|" + ORG_A: {"rt-2-fp-placeholder": "x",
                                             P.fingerprint(tried.entry): "2026-10-30"}})
    assert [a.source.machine for a in actions] == ["vm2"]


def test_an_active_login_wiped_by_claude_code_is_repaired_and_reactivated():
    mine = login("a@x", ORG_A, "rt-dead", OLD, number=3)
    good = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER))
    actions = P.plan([row(mine, "no_credentials", active=True)], {"accounts": []}, [good])
    assert [(a.kind, a.number) for a in actions] == [("repair-active", 3)]


def test_no_credentials_on_an_inactive_slot_is_not_a_repair():
    mine = login("a@x", ORG_A, "rt-dead", OLD)
    good = copy_("laptop", login("a@x", ORG_A, "rt-2", NEWER))
    assert P.plan([row(mine, "no_credentials")], {"accounts": []}, [good]) == []


def test_logins_are_matched_by_email_and_organization():
    mine = login("m@x", ORG_A, "rt-dead", OLD)
    other_org = copy_("laptop", login("m@x", ORG_B, "rt-9", NEWER))
    actions = P.plan([row(mine, "relogin_required")], {"accounts": [mine]}, [other_org],
                     add_missing=False)
    assert actions == []


def test_missing_logins_are_added_unless_switched_off_or_excluded():
    mine = login("a@x", ORG_A, "rt-1", OLD)
    extra = copy_("laptop", login("m@x", ORG_B, "rt-9", NEWER, number=7))
    rows, exp = [row(mine)], {"accounts": [mine]}
    assert [(a.kind, a.email) for a in P.plan(rows, exp, [extra])] == [("add", "m@x")]
    assert P.plan(rows, exp, [extra], add_missing=False) == []
    assert P.plan(rows, exp, [extra], exclude=["M@x"]) == []
    assert P.plan(rows, exp, [extra], exclude=["m@x/bbbb"]) == []
    assert P.plan(rows, exp, [extra], exclude=["m@x/aaaa"]) != []


def test_only_working_oauth_logins_are_published():
    ok = login("a@x", ORG_A, "rt-1", NEW, number=1)
    dead = login("b@x", ORG_A, "rt-2", NEW, number=2)
    rows = [row(ok), row(dead, "relogin_required"),
            {"number": 3, "email": "k@token.local", "organizationUuid": "", "usageStatus": "api_key"}]
    exp = {"accounts": [dict(ok, kind="oauth"), dead,
                        {"number": 3, "email": "k@token.local", "kind": "api_key",
                         "credentials": "sk-ant-api03-x", "config": {}}]}
    pub = P.publication("vm1", rows, exp, "now")
    assert [e["email"] for e in pub["accounts"]] == ["a@x"]
    assert "kind" not in pub["accounts"][0]


def test_digest_changes_only_with_the_token_generations():
    a = login("a@x", ORG_A, "rt-1", NEW)
    p1 = P.publication("m", [row(a)], {"accounts": [a]}, "t1")
    p2 = P.publication("m", [row(a)], {"accounts": [a]}, "t2")
    b = login("a@x", ORG_A, "rt-2", NEWER)
    p3 = P.publication("m", [row(b)], {"accounts": [b]}, "t3")
    assert P.digest(p1) == P.digest(p2) != P.digest(p3)


def test_remote_entries_without_a_usable_login_are_ignored():
    good = login("a@x", ORG_A, "rt-1", NEW)
    pub = {"format": 1, "machine": "m", "publishedAt": "t", "accounts": [
        good, {"email": "b@x", "credentials": "sk-ant-api03-x"}, "junk",
        {"email": "", "credentials": good["credentials"]}]}
    assert [c.identity[0] for c in P.remote_copies("m", pub)] == ["a@x"]
    assert P.remote_copies("m", dict(pub, format=2)) == []


def test_the_import_envelope_is_cswap_format_1_without_an_active_account():
    env = P.envelope([dict(login("a@x", ORG_A, "rt-1", NEW), extra="dropped")], "cswap-sync:m", "t")
    assert env["version"] == 1 and env["encrypted"] is False
    assert env["activeAccountNumber"] is None
    assert "extra" not in env["accounts"][0]
