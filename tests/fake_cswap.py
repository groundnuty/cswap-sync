#!/usr/bin/env python3
"""A stand-in cswap executable for CLI tests. State lives in $FAKE_CSWAP_STATE:
{"entries": [...export entries...], "statuses": {"num": status}, "active": num}."""

import json
import os
import sys

path = os.environ["FAKE_CSWAP_STATE"]
state = json.load(open(path))
args = sys.argv[1:]
log = state.setdefault("calls", [])
log.append(args)


def save():
    json.dump(state, open(path, "w"))


if args[:2] == ["list", "--json"]:
    rows = [{"number": e["number"], "email": e["email"], "organizationUuid": e["organizationUuid"],
             "organizationName": e.get("organizationName", ""),
             "active": e["number"] == state.get("active"),
             "usageStatus": state["statuses"].get(str(e["number"]), "ok")} for e in state["entries"]]
    print(json.dumps({"accounts": rows}))
elif args[:2] == ["export", "-"]:
    if state.get("export_fails") and "--account" not in args:
        print("failed to read live credentials", file=sys.stderr)
        save()
        sys.exit(1)
    entries = state["entries"]
    if "--account" in args:
        entries = [e for e in entries if str(e["number"]) == args[args.index("--account") + 1]]
    print(json.dumps({"version": 1, "accounts": entries}))
elif args[:2] == ["import", "-"]:
    env = json.load(sys.stdin)
    for new in env["accounts"]:
        for i, e in enumerate(state["entries"]):
            if (e["email"], e["organizationUuid"]) == (new["email"], new["organizationUuid"]):
                new["number"] = e["number"]
                state["entries"][i] = new
                state["statuses"][str(e["number"])] = "ok"
                print(f"Replaced {new['email']} (slot {e['number']} was quarantined)", file=sys.stderr)
                break
        else:
            new["number"] = max([e["number"] for e in state["entries"]] + [0]) + 1
            state["entries"].append(new)
            print(f"Imported {new['email']} → slot {new['number']}", file=sys.stderr)
    print("Done: 1 imported, 0 overwritten, 0 skipped", file=sys.stderr)
elif args[:1] == ["switch"]:
    pass
else:
    print(f"fake cswap: unsupported {args}", file=sys.stderr)
    save()
    sys.exit(2)
save()
