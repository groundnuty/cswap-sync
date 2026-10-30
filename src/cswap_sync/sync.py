"""One sync pass: publish this machine's working logins, read the others',
and replace dead local logins with working copies."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Callable

from cswap_sync import plan as P
from cswap_sync.crypto import DecryptError, seal, unseal
from cswap_sync.cswap import CswapError
from cswap_sync.store import StoreError

TRIED_TTL_DAYS = 30


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def short_time(ms: int) -> str:
    if not ms:
        return "-"
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%m-%d %H:%MZ")


def describe(a: P.Action) -> str:
    src = a.source
    where = f"from {src.machine} (rt {src.fingerprint[:8]}, token exp {short_time(src.expires_at)})"
    org = a.organization[:8] or "personal"
    if a.kind == "add":
        return f"add {a.email} [{org}] {where}"
    return f"{a.kind} #{a.number} {a.email} [{org}], here {a.status}, {where}"


@dataclass
class Pass:
    published: bool = False
    published_count: int = 0
    remotes: dict[str, list[P.Copy]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    actions: list[P.Action] = field(default_factory=list)
    applied: list[str] = field(default_factory=list)
    accounts: list[dict] = field(default_factory=list)
    local_export: dict = field(default_factory=dict)


def _prune(tried: dict) -> dict:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=TRIED_TTL_DAYS)).isoformat()
    out = {}
    for ident, fps in tried.items():
        kept = {fp: t for fp, t in fps.items() if t >= cutoff}
        if kept:
            out[ident] = kept
    return out


def run_pass(cswap, store, key: bytes, machine: str, state: dict, *,
             publish: bool = True, apply: bool = True, add_missing: bool = True,
             exclude: list[str] | None = None,
             log: Callable[[str], None] = print) -> Pass:
    """`state` is mutated in place: the last published digest and, per
    login, the copies already tried."""
    result = Pass()
    accounts = cswap.accounts()
    local_export = cswap.export(accounts)
    result.accounts, result.local_export = accounts, local_export

    if publish:
        pub = P.publication(machine, accounts, local_export, now_iso())
        result.published_count = len(pub["accounts"])
        d = P.digest(pub)
        if d != state.get("published"):
            store.write(machine, seal(key, machine, json.dumps(pub).encode()))
            state["published"] = d
            result.published = True
            log(f"published {result.published_count} working login(s) to {store}")

    copies: list[P.Copy] = []
    for m in store.machines():
        if m == machine:
            continue
        try:
            pub = json.loads(unseal(key, m, store.read(m)))
        except (StoreError, DecryptError, ValueError) as e:
            result.skipped.append(f"{m}: {e}")
            log(f"skipped {m}: {e}")
            continue
        if not isinstance(pub, dict) or pub.get("machine") != m:
            result.skipped.append(f"{m}: names another machine")
            continue
        result.remotes[m] = P.remote_copies(m, pub)
        copies.extend(result.remotes[m])

    state["tried"] = _prune(state.get("tried", {}))
    result.actions = P.plan(accounts, local_export, copies, add_missing=add_missing,
                            exclude=exclude, tried=state["tried"])
    for a in result.actions:
        log(("" if apply else "would ") + describe(a))
        if not apply:
            continue
        # Recorded before the import, so a copy that fails is never retried.
        state["tried"].setdefault(P.identity_key(a.identity), {})[a.source.fingerprint] = now_iso()
        env = P.envelope([a.source.entry], f"cswap-sync:{a.source.machine}", now_iso())
        try:
            lines = cswap.import_envelope(env, force=(a.kind == "repair-active"))
            for ln in lines:
                if ln.startswith(("Imported", "Replaced", "Overwrote", "Skipped", "Done")):
                    log(f"  cswap: {ln}")
            if a.kind == "repair-active":
                cswap.activate(a.number)
                log(f"  cswap: live login of #{a.number} rewritten from the imported copy")
            result.applied.append(describe(a))
        except CswapError as e:
            log(f"  failed: {e}")
    return result
