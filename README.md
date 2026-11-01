# Camellia Remote Server

Camellia Remote Server provides the identity/rendezvous and relay data plane for
Camellia Remote. It is an AGPL-3.0-only derivative of RustDesk Server OSS and
uses the separately versioned `camellia-remote-protocol` submodule.

The repository is a clean pre-release baseline. It does not import old runtime
databases, old package names, or compatibility service units.

## Components

| Binary | Purpose | Default listeners |
|---|---|---|
| `camellia-remote-identity` | device registration, rendezvous, NAT testing and WebSocket rendezvous | 21115/TCP, 21116/TCP+UDP, 21118/TCP |
| `camellia-remote-relay` | encrypted session relay and WebSocket relay | 21117/TCP, 21119/TCP |
| `camellia-remote-utils` | key generation, key validation, diagnostics and TCP health checks | none |

Build and verify the exact locked graph with Rust 1.97.1:

```bash
cargo build --locked --release --bins
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

## Configuration

Configuration values follow strict precedence: command-line arguments take
precedence over process environment variables, which take precedence over
explicit configuration files, followed by defaults (`CLI > environment >
config file > defaults`).

To specify a configuration file, use `--config <FILE>` / `-c <FILE>` or set the
`CAMELLIA_REMOTE_CONFIG_FILE` environment variable. Implicit or ambient `.env`
files in the working directory are not automatically loaded. Configuration files
must be regular files, must not be group- or world-writable, and on Unix systems
must be owned by `root` (UID 0) or the running process's effective UID. Production
services should use a root-owned environment file and secret files instead.

Important settings:

- `CAMELLIA_REMOTE_KEY`: `_` or `-` loads or atomically generates
  `id_ed25519`/`id_ed25519.pub`; an explicit identity key must be a valid
  Ed25519 private key.
- `CAMELLIA_REMOTE_IDENTITY_PORT`: identity base port, default 21116.
- `CAMELLIA_REMOTE_RELAY_PORT`: relay base port, default 21117.
- `CAMELLIA_REMOTE_RELAY_SERVERS`: public relay `host:port` values advertised to clients.
- `CAMELLIA_REMOTE_API_SERVER`: bare management API origin. Non-loopback HTTP is rejected.
- `CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE`: shared high-entropy verification secret.
- `CAMELLIA_REMOTE_TRUST_PROXY_HEADERS`: keep `N` unless a trusted proxy overwrites client
  address headers.
- `CAMELLIA_REMOTE_DB_URL`: identity SQLite path. The clean default is
  `./camellia-remote.sqlite3`.

See [the complete environment reference](docs/environment-variables.md).

## Production deployment

The Compose model requires an immutable image digest and runs both services as
UID/GID 10001 with no capabilities, a read-only root filesystem, bounded PIDs,
health checks, and one shared persistent state volume.

```bash
export CAMELLIA_REMOTE_SERVER_IMAGE='ghcr.io/<owner>/<repository>@sha256:<digest>'
export CAMELLIA_REMOTE_RELAY_ADDRESS='remote.example.com:21117'
export CAMELLIA_REMOTE_API_SERVER='https://api.example.com'
export CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE='/secure/device-verification-token'
docker compose up -d
```

For a native deployment, install the three release binaries, create the
unprivileged `camellia-remote` account, install
`deploy/systemd/*.service`, and place a mode-0600 configuration at
`/etc/camellia-remote/server.env`. Start the relay before the identity
service:

```bash
sudo systemctl enable --now camellia-remote-relay.service
sudo systemctl enable --now camellia-remote-identity.service
```

TLS should terminate at a hardened reverse proxy where WebSocket ingress is
needed. Expose only the required ports and retain host/firewall rate controls.
Never put the private server key or device-verification token in an image,
repository, log, or command history.

## Availability and recovery

The initial production target is one region with a 99.9% service objective,
RPO no greater than one hour, and RTO no greater than four hours. At least
hourly, take an encrypted, integrity-checked snapshot of the entire persistent
state as one recovery point: SQLite database, Ed25519 key pair, and any
operator-managed configuration. Store the image digest, protocol submodule
commit, application commit, and snapshot checksum beside it.

Quarterly and after storage/release changes, restore into an isolated host,
verify key permissions, run `camellia-remote-utils validatekeypair`, start
both services from the recorded image digest, and exercise registration,
rendezvous, direct/relay connection, and management API verification. A
rollback changes the immutable image digest; it never edits the database or
moves a release tag.

## Release flow

The companion client repository owns the cross-repository production-readiness
audit. The exact server candidate, publication, recovery, and
independent-verification contract is documented in
[the release process](docs/release-process.md).

Pull requests and `main` pushes run formatting, Clippy, all tests, metadata
checks, release-state-machine regression tests, the production image build,
vulnerability scanning, Compose validation, systemd hardening checks, and one
stable `CI / Required` aggregate gate. A successful `main` CI lets the Release
App open a generated `release/next` PR; exact-head CI and human approval are
required before its SHA-guarded squash merge. The App then prepares the draft
Release and lightweight stable tag.

The tag workflow freezes one multi-architecture OCI layout, scans it, produces
SBOM/provenance and protocol-dependency evidence, then enters the protected
`release` environment. Each registry configured in the reviewed logical map is
published by the same digest and keylessly signed. GitHub Release assets are
signed and read back before immutable completion. `latest` is reconciled only
to the highest completed version and is never a deployment input. Full
state-machine and recovery rules are in
[the release process](docs/release-process.md).

## License and provenance

Camellia changes and the inherited server code are licensed
[AGPL-3.0-only](LICENSE). Upstream copyright and attribution are retained in
[NOTICE](NOTICE), with the exact import recorded in
[SOURCE_PROVENANCE.json](SOURCE_PROVENANCE.json). Network deployment therefore
carries AGPL source-availability obligations. Required CI rejects any mismatch
between that record and the checked-out protocol submodule.
