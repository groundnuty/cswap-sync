"""What to publish, and which local logins to replace. Pure functions over
cswap's own JSON (`cswap list --json` rows and `cswap export` entries).

Policy, the same as the manual export/import routine it replaces:
- publish only logins that cswap reports as working here ("ok");
- replace a local login only when cswap reports it dead: quarantined after
  `invalid_grant` ("relogin_required"), or, for the active account, a live
  login that Claude Code wiped ("no_credentials");
- add a login this machine lacks (unless switched off or excluded);
- never touch a working local login, and never try the same copy twice.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

FORMAT = 1
HEALTHY = "ok"
DEAD = "relogin_required"
EMPTY = "no_credentials"
ENTRY_FIELDS = ("number", "email", "uuid", "organizationUuid", "organizationName",
                "added", "alias", "credentials", "config")

Identity = tuple[str, str]  # (email, organization uuid)


def identity_of(row: dict) -> Identity:
    return (str(row.get("email", "")).lower(), str(row.get("organizationUuid") or ""))


def identity_key(ident: Identity) -> str:
    return f"{ident[0]}|{ident[1]}"


def oauth_of(entry: dict) -> dict | None:
    creds = entry.get("credentials")
    if isinstance(creds, dict) and isinstance(creds.get("claudeAiOauth"), dict):
        return creds["claudeAiOauth"]
    return None


def fingerprint(entry: dict) -> str:
    """Short hash naming one token generation; safe to print and store."""
    o = oauth_of(entry) or {}
    secret = o.get("refreshToken") or o.get("accessToken") or ""
    return hashlib.sha256(secret.encode()).hexdigest()[:12] if secret else ""


def expires_at(entry: dict) -> int:
    v = (oauth_of(entry) or {}).get("expiresAt")
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


def _clean(entry: dict) -> dict:
    return {k: entry[k] for k in ENTRY_FIELDS if k in entry}


def working_entries(accounts: list[dict], export: dict) -> list[dict]:
    """Export entries for OAuth logins that cswap reports as working here."""
    ok = {identity_of(a) for a in accounts if a.get("usageStatus") == HEALTHY}
    return [
        _clean(e) for e in export.get("accounts", [])
        if isinstance(e, dict) and e.get("kind") != "api_key"
        and oauth_of(e) and fingerprint(e) and identity_of(e) in ok
    ]


def publication(machine: str, accounts: list[dict], export: dict, now_iso: str) -> dict:
    return {"format": FORMAT, "machine": machine, "publishedAt": now_iso,
            "accounts": working_entries(accounts, export)}


def digest(pub: dict) -> str:
    """Changes only when the set of published token generations changes."""
    gens = sorted((identity_key(identity_of(e)), fingerprint(e), expires_at(e))
                  for e in pub["accounts"])
    return hashlib.sha256(json.dumps(gens).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Copy:
    machine: str
    entry: dict
    published_at: str = ""

    @property
    def identity(self) -> Identity:
        return identity_of(self.entry)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.entry)

    @property
    def expires_at(self) -> int:
        return expires_at(self.entry)


@dataclass(frozen=True)
class Action:
    kind: str                 # "repair", "repair-active" or "add"
    email: str
    organization: str
    number: int | None        # local slot; None for "add"
    status: str | None        # local usageStatus; None for "add"
    source: Copy

    @property
    def identity(self) -> Identity:
        return (self.email, self.organization)


def remote_copies(machine: str, publication_: dict) -> list[Copy]:
    if not isinstance(publication_, dict) or publication_.get("format") != FORMAT:
        return []
    out = []
    for e in publication_.get("accounts") or []:
        if (isinstance(e, dict) and isinstance(e.get("email"), str) and e["email"]
                and oauth_of(e) and fingerprint(e)):
            out.append(Copy(machine, _clean(e), str(publication_.get("publishedAt", ""))))
    return out


def best_copies(copies: list[Copy]) -> dict[Identity, list[Copy]]:
    """Copies per login, newest token generation first."""
    by_ident: dict[Identity, list[Copy]] = {}
    for c in copies:
        by_ident.setdefault(c.identity, []).append(c)
    for lst in by_ident.values():
        lst.sort(key=lambda c: (c.expires_at, c.published_at), reverse=True)
    return by_ident


def _excluded(ident: Identity, exclude: list[str]) -> bool:
    email, org = ident
    for rule in exclude:
        r_email, _, r_org = rule.lower().partition("/")
        if r_email == email and (not r_org or org.startswith(r_org)):
            return True
    return False


def plan(accounts: list[dict], local_export: dict, copies: list[Copy], *,
         add_missing: bool = True, exclude: list[str] | None = None,
         tried: dict[str, dict] | None = None) -> list[Action]:
    exclude = exclude or []
    tried = tried or {}
    local_fp = {identity_of(e): fingerprint(e) for e in local_export.get("accounts", [])
                if isinstance(e, dict)}
    candidates = best_copies(copies)

    def pick(ident: Identity) -> Copy | None:
        seen = tried.get(identity_key(ident), {})
        for c in candidates.get(ident, []):
            if c.fingerprint != local_fp.get(ident) and c.fingerprint not in seen:
                return c
        return None

    actions: list[Action] = []
    for a in accounts:
        status = a.get("usageStatus")
        active = bool(a.get("active"))
        if not (status == DEAD or (active and status == EMPTY)):
            continue
        ident = identity_of(a)
        if _excluded(ident, exclude):
            continue
        src = pick(ident)
        if src:
            actions.append(Action("repair-active" if active else "repair", ident[0], ident[1],
                                  a.get("number"), status, src))

    if add_missing:
        here = {identity_of(a) for a in accounts}
        for ident in sorted(candidates):
            if ident in here or _excluded(ident, exclude):
                continue
            src = pick(ident)
            if src:
                actions.append(Action("add", ident[0], ident[1], None, None, src))
    return actions


def envelope(entries: list[dict], source: str, now_iso: str) -> dict:
    """A cswap export envelope (format 1) for `cswap import -`."""
    return {"version": 1, "exportedAt": now_iso, "exportedFrom": source,
            "swapVersion": "cswap-sync", "encrypted": False,
            "activeAccountNumber": None, "accounts": [_clean(e) for e in entries]}
