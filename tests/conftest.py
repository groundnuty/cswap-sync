import copy

import pytest

from cswap_sync.crypto import load_key, new_key

ORG_A = "aaaa1111-0000-0000-0000-000000000000"
ORG_B = "bbbb2222-0000-0000-0000-000000000000"


def login(email, org, rt, exp, number=1, at=None):
    """A cswap export entry for one OAuth login."""
    return {
        "number": number, "email": email, "uuid": "u-" + email, "organizationUuid": org,
        "organizationName": "Org " + org[:4], "added": "2026-10-01T00:00:00",
        "credentials": {"claudeAiOauth": {"accessToken": at or "at-" + rt,
                                          "refreshToken": rt, "expiresAt": exp}},
        "config": {"oauthAccount": {"emailAddress": email, "organizationUuid": org}},
    }


def row(entry, status="ok", active=False):
    """The matching `cswap list --json` row."""
    return {"number": entry["number"], "email": entry["email"],
            "organizationUuid": entry["organizationUuid"],
            "organizationName": entry["organizationName"],
            "active": active, "usageStatus": status}


class FakeCswap:
    """Stands in for the cswap CLI: rows and stored logins in memory."""

    def __init__(self, entries, statuses=None, active=None, api_keys=()):
        self.entries = [copy.deepcopy(e) for e in entries]
        self.statuses = dict(statuses or {})
        self.active = active
        self.api_keys = list(api_keys)
        self.imports = []
        self.activated = []

    def accounts(self):
        rows = [row(e, self.statuses.get(e["number"], "ok"), e["number"] == self.active)
                for e in self.entries]
        rows += [{"number": n, "email": "key@token.local", "organizationUuid": "",
                  "active": False, "usageStatus": "api_key"} for n in self.api_keys]
        return rows

    def export(self, accounts):
        out = [copy.deepcopy(e) for e in self.entries]
        out += [{"number": n, "email": "key@token.local", "kind": "api_key",
                 "credentials": "sk-ant-api03-x", "config": {}} for n in self.api_keys]
        return {"accounts": out}

    def import_envelope(self, envelope, force=False):
        self.imports.append((copy.deepcopy(envelope), force))
        lines = []
        for new in envelope["accounts"]:
            key = (new["email"], new["organizationUuid"])
            for i, e in enumerate(self.entries):
                if (e["email"], e["organizationUuid"]) == key:
                    if force or self.statuses.get(e["number"]) == "relogin_required":
                        self.entries[i] = dict(copy.deepcopy(new), number=e["number"])
                        self.statuses[e["number"]] = "ok"
                        lines.append(f"Replaced {new['email']} (slot {e['number']})")
                    else:
                        lines.append(f"Skipped {new['email']} (already exists, use --force)")
                    break
            else:
                n = max([e["number"] for e in self.entries] + self.api_keys + [0]) + 1
                self.entries.append(dict(copy.deepcopy(new), number=n))
                lines.append(f"Imported {new['email']} -> slot {n}")
        return lines

    def activate(self, number):
        self.activated.append(number)


@pytest.fixture
def key():
    return load_key(new_key())
