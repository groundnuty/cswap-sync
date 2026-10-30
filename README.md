# cswap-sync

Keeps [claude-swap](https://github.com/realiti4/claude-swap) logins alive across several machines. It automates the manual routine of exporting a login from a machine where it still works and importing it on a machine where it died.

Each machine publishes its **working** logins, encrypted, to a shared store. On every pass it reads the other machines' copies and repairs its own logins:

- a login cswap reports as dead here (`relogin_required`, or an active login that Claude Code wiped) is replaced with the newest working copy from another machine;
- a login this machine does not have is added (switch off with `--no-add-missing`, or skip some with `--exclude`);
- a working login is never touched, and a copy that was already tried is never imported again.

All changes go through cswap itself: `cswap import -` (which only replaces a slot cswap has quarantined as dead) and, for the active account, `cswap switch N --force`. API-key accounts are never published.

## Store and secrets

- **Store:** a private GitHub repo, reached through the contents API with a fine-grained personal access token limited to that one repo (*Contents: read and write*). Each machine writes only `machines/<name>.enc`. A plain directory (`dir:PATH`) also works.
- **Sync key:** one random 32-byte key shared by all machines. Published files are AES-256-GCM encrypted with it and bound to the publishing machine's name. The repo token alone reveals nothing and cannot forge a login.
- Files in `~/.config/cswap-sync/` (mode 600): `key`, `github-token`, `config.json`, `state.json`.

## Set up

```sh
uv tool install "git+https://github.com/groundnuty/cswap-sync"   # on each machine

cswap-sync keygen                                   # once, on one machine
ssh HOST 'umask 077; mkdir -p ~/.config/cswap-sync; cat > ~/.config/cswap-sync/key' < ~/.config/cswap-sync/key
ssh HOST 'umask 077; cat > ~/.config/cswap-sync/github-token' < ~/.config/cswap-sync/github-token

echo '{"store": "github:OWNER/REPO"}' > ~/.config/cswap-sync/config.json
```

`config.json` may also set `machine` (default: short hostname), `add_missing` (default `true`), `exclude` (a list of `email` or `email/org-uuid-prefix`), `interval` (seconds, default 300) and `cswap` (the executable).

## Use

```sh
cswap-sync status          # who holds which login, and what a run would do; changes nothing
cswap-sync publish         # publish this machine's working logins; changes nothing here
cswap-sync run             # one pass: publish, then repair
cswap-sync run --loop      # every 5 minutes, e.g. in a tmux pane next to `cswap watch`
```

Output names logins by email and a short SHA-256 fingerprint of the refresh token. Tokens are never printed.

## Tests

```sh
uv run pytest
```
