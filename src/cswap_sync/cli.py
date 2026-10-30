"""cswap-sync command line.

  cswap-sync keygen          create the sync key (once, then copy it to every machine)
  cswap-sync status          who holds which login; what a run would do (changes nothing)
  cswap-sync publish         publish this machine's working logins, change nothing here
  cswap-sync run [--loop]    publish, then replace dead logins here with working copies
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path

from cswap_sync import __version__
from cswap_sync import plan as P
from cswap_sync.crypto import load_key, new_key
from cswap_sync.cswap import Cswap, CswapError
from cswap_sync.store import StoreError, check_machine, open_store
from cswap_sync.sync import describe, now_iso, run_pass, short_time

DEFAULT_DIR = "~/.config/cswap-sync"


def log(msg: str) -> None:
    print(f"{now_iso()}  {msg}", flush=True)


def _secret_file(path: Path, what: str) -> str:
    if not path.exists():
        raise SystemExit(f"cswap-sync: {what} not found at {path}")
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit(f"cswap-sync: {path} is readable by others; run: chmod 600 {path}")
    return path.read_text().strip()


def _load_config(cdir: Path) -> dict:
    f = cdir / "config.json"
    if not f.exists():
        return {}
    try:
        cfg = json.loads(f.read_text())
    except ValueError as e:
        raise SystemExit(f"cswap-sync: {f}: {e}") from None
    return cfg if isinstance(cfg, dict) else {}


def _state(cdir: Path) -> tuple[Path, dict]:
    f = cdir / "state.json"
    try:
        return f, json.loads(f.read_text())
    except (OSError, ValueError):
        return f, {}


def _save_state(f: Path, state: dict) -> None:
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    os.chmod(tmp, 0o600)
    os.replace(tmp, f)


def _settings(args) -> dict:
    cdir = Path(args.config_dir).expanduser()
    cfg = _load_config(cdir)
    store_spec = args.store or os.environ.get("CSWAP_SYNC_STORE") or cfg.get("store")
    if not store_spec:
        raise SystemExit("cswap-sync: no store; pass --store or set \"store\" in "
                         f"{cdir / 'config.json'}")
    machine = check_machine(args.machine or cfg.get("machine") or socket.gethostname().split(".")[0])
    token = os.environ.get("CSWAP_SYNC_GITHUB_TOKEN")
    if store_spec.startswith("github:") and not token:
        token = _secret_file(cdir / "github-token", "GitHub token")
    exclude = list(cfg.get("exclude") or []) + list(args.exclude or [])
    add_missing = cfg.get("add_missing", True) and not args.no_add_missing
    return {
        "dir": cdir,
        "store": open_store(store_spec, token),
        "key": load_key(_secret_file(cdir / "key", "sync key")),
        "machine": machine,
        "exclude": exclude,
        "add_missing": add_missing,
        "interval": getattr(args, "interval", None) or cfg.get("interval") or 300,
        "cswap": Cswap(args.cswap or cfg.get("cswap") or "cswap"),
    }


def cmd_keygen(args) -> int:
    cdir = Path(args.config_dir).expanduser()
    f = cdir / "key"
    if f.exists():
        print(f"cswap-sync: {f} already exists; not overwriting", file=sys.stderr)
        return 1
    cdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(new_key() + "\n")
    print(f"Created {f}. Copy it to every machine without printing it, e.g.:\n"
          f"  ssh HOST 'umask 077; mkdir -p {DEFAULT_DIR}; cat > {DEFAULT_DIR}/key' < {f}")
    return 0


def _show(s: dict, res) -> None:
    here = s["machine"]
    fps = {P.identity_of(e): (P.fingerprint(e), P.expires_at(e))
           for e in res.local_export.get("accounts", []) if isinstance(e, dict)}
    rows: dict[P.Identity, list[str]] = {}
    names: dict[P.Identity, str] = {}
    for a in res.accounts:
        if a.get("usageStatus") == "api_key":
            continue
        ident = P.identity_of(a)
        names[ident] = a.get("organizationName") or ident[1][:8] or "personal"
        fp, exp = fps.get(ident, ("", 0))
        rows.setdefault(ident, []).append(
            f"{here + ' (here)':<24} #{a['number']:<3}{'*' if a.get('active') else ' '} "
            f"{a.get('usageStatus', '?'):<17} rt {fp[:8] or '-':<8}  token exp {short_time(exp)}")
    for m, copies in sorted(res.remotes.items()):
        for c in copies:
            names.setdefault(c.identity, c.entry.get("organizationName") or c.identity[1][:8])
            rows.setdefault(c.identity, []).append(
                f"{m:<24} #{c.entry.get('number', '?'):<4} {'published ' + c.published_at[5:16] + 'Z':<17} "
                f"rt {c.fingerprint[:8]:<8}  token exp {short_time(c.expires_at)}")
    print(f"store {s['store']}; this machine: {here}; machines publishing: "
          f"{', '.join(sorted(res.remotes)) or 'none yet'}")
    for ident in sorted(rows):
        print(f"\n{ident[0]}  [{names.get(ident, '')}]")
        for r in rows[ident]:
            print(f"  {r}")
    for sk in res.skipped:
        print(f"\nskipped {sk}")
    print("\nplan: " + ("nothing to do" if not res.actions else ""))
    for a in res.actions:
        print(f"  {describe(a)}")


def _locked(cdir: Path):
    cdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fh = open(cdir / ".lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("cswap-sync: another cswap-sync is running on this machine") from None
    return fh


def _one(s: dict, *, publish: bool, apply: bool, quiet_log=None):
    state_file, state = _state(s["dir"])
    res = run_pass(s["cswap"], s["store"], s["key"], s["machine"], state,
                   publish=publish, apply=apply, add_missing=s["add_missing"],
                   exclude=s["exclude"], log=quiet_log or log)
    if publish or apply:
        _save_state(state_file, state)
    return res


def cmd_status(args) -> int:
    s = _settings(args)
    res = _one(s, publish=False, apply=False, quiet_log=lambda _m: None)
    _show(s, res)
    return 0


def cmd_publish(args) -> int:
    s = _settings(args)
    _lock = _locked(s["dir"])
    res = _one(s, publish=True, apply=False, quiet_log=lambda _m: None)
    log(f"{'published' if res.published else 'unchanged:'} {res.published_count} working login(s) "
        f"in {s['store']}")
    return 0


def cmd_run(args) -> int:
    s = _settings(args)
    _lock = _locked(s["dir"])
    if not args.loop:
        _one(s, publish=True, apply=True)
        return 0
    log(f"cswap-sync {__version__}: {s['machine']} syncing with {s['store']} every {s['interval']} s")
    while True:
        try:
            _one(s, publish=True, apply=True)
        except (CswapError, StoreError, OSError, ValueError) as e:
            log(f"pass failed: {e}")
        time.sleep(s["interval"])


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config-dir", default=os.environ.get("CSWAP_SYNC_DIR", DEFAULT_DIR))
    common.add_argument("--store", help="github:OWNER/REPO or dir:PATH")
    common.add_argument("--machine", help="name to publish under (default: short hostname)")
    common.add_argument("--cswap", help="cswap executable (default: cswap on PATH)")
    common.add_argument("--no-add-missing", action="store_true",
                        help="only repair dead logins; never add logins this machine lacks")
    common.add_argument("--exclude", action="append", metavar="EMAIL[/ORG]",
                        help="never repair or add this login (repeatable)")
    p = argparse.ArgumentParser(prog="cswap-sync", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"cswap-sync {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", parents=[common], help="create the sync key")
    sub.add_parser("status", parents=[common],
                   help="show logins across machines and the plan; changes nothing")
    sub.add_parser("publish", parents=[common], help="publish this machine's working logins only")
    r = sub.add_parser("run", parents=[common], help="publish, then repair dead logins here")
    r.add_argument("--loop", action="store_true", help="repeat every --interval seconds")
    r.add_argument("--interval", type=int, help="seconds between passes (default 300)")
    args = p.parse_args(argv)
    try:
        return {"keygen": cmd_keygen, "status": cmd_status, "publish": cmd_publish,
                "run": cmd_run}[args.cmd](args)
    except (CswapError, StoreError, ValueError) as e:
        print(f"cswap-sync: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
