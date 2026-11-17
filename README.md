# Argus Client (Rust)

Self-contained **Rust** client-side supervisor for Argus Center. Chisel is the initial transport adapter, not the application itself. Pair credentials and service definitions persist as machine-local files, not VM environment variables.

## Setup (first pairing only)

```sh
cargo build --release
argus-client enroll --center https://argus.example.com --token <ONE_TIME_TOKEN>
argus-client list
argus-client run --pair example-client --chisel /path/to/chisel
```

Run is self-healing: it reconnects on transport exit, checks local services and polls the center for new revisions every 30 seconds. For restricted cloud egress, enrollment snapshots the existing HTTPS_PROXY into a private local state file for Chisel; existing enrolled pairs can run `argus-client proxy-capture --pair muse` once. This does not expose credentials in the public GitHub repository. After a `service-add`, only this client's reverse transport restarts.

`argus-client install-service --pair example-client` generates a systemd user service on Linux or a Windows logon scheduled task. For headless Linux VMs without a systemd user session, run the CLI as root with `argus-client --state-dir /path/to/private-state install-service --pair muse --chisel /absolute/path/to/chisel --system`. This installs a boot-enabled system service (`WantedBy=multi-user.target`, `Restart=always`, restrictive umask); it does not depend on VM environment variables. Use only with a trusted local state file and reviewed watchdog scripts, since the system service has the invoker’s (root) privileges. **Ephemeral providers must still invoke the installed binary at VM/task startup; a deleted VM cannot reboot itself.**
`argus-client check --pair example-client` prints non-secret diagnostic state.
`argus-client sync --pair example-client` requests a configuration refresh without executing a VM restoration script.

The client stores its state in the OS user's home directory under `.argus-client` by default, or `--state-dir`. The server's SSH host fingerprint is pinned; transport authentication is distinct from Orca E2EE. No Python is used.

Source: https://github.com/tibame201020/argus-center

## v0.2: Private watchdog scripts

```sh
# Center operator has configured the script and bumped a pair revision:
argus-client --state-dir ./state sync --pair muse

# Inspect the VM-local service without executing any repair:
argus-client --state-dir ./state watchdog --pair muse --check-only

# Run only configured restore scripts for unhealthy services:
argus-client --state-dir ./state watchdog --pair muse
```

Scripts are SHA-256 checked and saved private (0700 on Unix). The running supervisor checks each service every 30 seconds and invokes only its configured script after two consecutive TCP failures, subject to cooldown. A successful script without a healthy listener is **not** counted as a restored service. The center has no remote shell; script installation is a deliberate administrative operation.

### Security

- Store credentials only in the private VM-local state dir, never in Git. The HTTPS proxy URL captured from the cloud environment may contain proxy credentials, so keep the entire state dir private.
- Scripts execute with the same OS privileges as the client. Audit and review the script before registering it.
- The Cloudflare/Argus HTTP proxy does **not** strip a service path automatically for every application protocol; test native Orca authenticated API separately from HTTP 200 and WebSocket 101.
- In ephemeral VMs, configure startup hooks to re-run the installer / watcher; an expired or deleted VM cannot autonomously recreate itself.

## Native Orca WSS authentication fixture

For an Orca process hosted on this VM and already published through Argus, run this **on the same VM** to verify that the full Argus route allows a native Orca pairing handshake, authenticated `status`, and protected `worktree list` API (without transmitting the pairing code to an operator or build logs):

```sh
bash tests/orca-auth-route.sh wss://argus.example.com/s/muse/orca
```

The test rotates only the unused local pairing offer; existing paired clients remain paired. This is a **VM → Center → same VM loop** test, not proof of PC → Center → VM authentication. It does not modify Oracle.

## Limitations (v0.2)

- Center routes HTTP/WebSocket services only; arbitrary TCP/SSH viewer-forward will be introduced as a separate authenticated adapter.
- Existing cloud VMs should use a new testing center without modifying their Oracle relay supervisor.
- Watchdog script injection is optional and opt-in through center configuration. No arbitrary existing service should be restarted before its check/restore procedure is verified.

## Client-initiated pair registration

If the Center already has the pair and the VM can reach its HTTPS endpoint,
use the client-initiated join with no pasted enrollment token:

    argus-client --state-dir /private/argus-state join --center https://argus.example.com --pair muse

The Client prints a public request commitment, not a private nonce. An
authorized Center operator verifies and approves that commitment from the
trusted target VM terminal. Client then persists scoped credentials and a
pinned Chisel host key, and can run as a persistent system service. VM
recreation must restore the service from its provider startup script;
existing state avoids re-enrollment.
