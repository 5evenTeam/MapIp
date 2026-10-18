# RemoteMap

RemoteMap is the consent-based remote host manager that ships inside the MapIp
binary. It is two halves:

- **`mapip remotemap host`** — the half you run *on the machine you want to
  reach*. You start it yourself, on purpose. It prints a banner, stays visible
  in your process list, and writes every accepted connection to its log.
- **`mapip remotemap client`** — the half that connects to a host agent.

RemoteMap is not a service. It is not installed silently. It does not survive
removal, it does not hide from the machine's owner, and it does not talk to
anything on the internet. Stopping the process stops RemoteMap.

## Design rules

- **Consent first.** The host agent only runs when the owner starts it.
- **Visible by default.** Every connection, authentication and operation is
  logged to stderr with a timestamp.
- **Encrypted.** AES-256-GCM with 256-bit keys derived through HKDF-SHA256.
- **Authenticated both ways.** The client proves the key with an HMAC-SHA256
  challenge/response, and the host proves it back. A wrong key is rejected
  before any data is sent.
- **No telemetry, no relay, no third parties.** The client connects directly to
  the address you give it.
- **Least privilege.** File access is confined to one directory (`--root`).
  Command execution is off unless the host owner passes `--allow-shell`.

## Setting up a host

Generate a key and start the agent:

```
mapip remotemap key --key-file ~/.mapip/remotemap/key.txt
mapip remotemap host --addr 0.0.0.0:8530 --key-file ~/.mapip/remotemap/key.txt --root ./shared
```

If you do not pass a key, the host creates one in the default location
(`%APPDATA%\MapIp\remotemap\key.txt` on Windows, the equivalent config
directory elsewhere) and prints it once so you can copy it to the client.

Host flags:

| Flag | Default | Description |
|---|---|---|
| `--addr` | `0.0.0.0:8530` | listen address |
| `--key` | — | pre-shared key (passphrase) |
| `--key-file` | config dir | read or create the key at this path |
| `--root` | current dir | the only directory clients may read |
| `--allow-shell` | false | permit `exec` on this host |
| `--allow` | any | comma-separated CIDR allow-list for clients |
| `--timeout` | `30s` | per-request idle timeout |

Both sides print the same short **key fingerprint** without revealing the key,
so you can confirm they match before you send anything:

```
key fingerprint  62e4b25b
```

## Using a client

```
mapip remotemap client --host 192.168.1.40 --key-file ~/.mapip/remotemap/key.txt info
mapip remotemap client --host 192.168.1.40 list ./logs
mapip remotemap client --host 192.168.1.40 get ./logs/app.log -o app.log
mapip remotemap client --host 192.168.1.40 exec "ipconfig /all"
mapip remotemap client --host 192.168.1.40 shell
```

Operations:

| Op | Description |
|---|---|
| `info` | hostname, OS, user, uptime, interfaces, shared root |
| `ping` | session liveness check |
| `list [path]` | list a directory inside the shared root |
| `get <remote> [-o local]` | download a file (`-o -` writes to stdout) |
| `exec <command>` | run one command (host must allow `--allow-shell`) |
| `shell` | interactive prompt; type `exit` to leave |

Client flags: `--host`, `--port`, `--key`, `--key-file`, `--timeout`,
`--exec-timeout`, `-o/--out`, `--json`.

In the interactive `shell`, a command line is executed remotely, and these
local commands are available:

- `:info` — print host details
- `:ls [path]` — list a directory
- `:get <remote> [local]` — download a file
- `exit` / `quit` — leave

## Security notes

- Use a long key. A generated key is 32 random bytes (64 hex characters). If you
  pass your own passphrase, prefer 16 or more characters.
- Keep the key file readable only by you. RemoteMap creates it with mode `0600`.
- Prefer `--allow` to restrict which addresses may connect when the host is not
  on a trusted network.
- `--allow-shell` is powerful. Leave it off unless you need it.
- MapIp is for hosts you own or are authorised to manage. Do not point
  RemoteMap at machines that are not yours.

## Limits

- No graphical desktop view, audio or clipboard. RemoteMap is a host-management
  channel, not a screen-sharing tool.
- Transfers are a single stream per request; there is no resume or parallel
  chunking.
- The wire protocol is versioned (`ProtocolVersion`), and both halves must come
  from the same MapIp release.
