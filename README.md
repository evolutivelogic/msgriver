# MsgRiver

MsgRiver is a self-hosted, durable message service for applications and
infrastructure. It accepts a message only after persisting it, deduplicates an
idempotency key, and delivers through operator-configured ntfy and WhatsApp
Cloud drivers.

`v0.1.0-alpha` is usable on Linux. It supports local Unix-socket intake with
durable acknowledgement and bounded retries, fixed-egress ntfy delivery,
fixed-template WhatsApp Cloud outbound delivery over verified TLS, and an
optional loopback WhatsApp callback endpoint. The callback verifies the raw
HMAC, permits only literal per-sender verbs, and has a persisted operator-only
switch, replay defense, and bounded diagnostic/status catalogue.

It is not a generic webhook proxy, command runner, or inbound chat system.

## Install

Install Rust 1.89 or newer, clone the repository, and build the binary:

```sh
git clone https://github.com/evolutivelogic/msgriver.git
cd msgriver
cargo build --release --locked -p msgriver
install -Dm755 target/release/msgriver /usr/local/bin/msgriver
```

Create an operator-owned state directory and start the service. The ntfy URL
and topic are fixed at startup; callers cannot select an endpoint.

```sh
install -d -m 700 /var/lib/msgriver
msgriver serve \
  --state-dir /var/lib/msgriver \
  --socket /var/lib/msgriver/msgriver.sock \
  --ntfy-url https://ntfy.example.net \
  --ntfy-topic operations
```

Submit a durable ntfy message through the local socket:

```sh
msgriver send --socket /var/lib/msgriver/msgriver.sock \
  --idempotency-key incident-2026-001 \
  --title MsgRiver --body 'A durable message was accepted.'
```

See [`deploy/msgriver.service.example`](deploy/msgriver.service.example) for a
minimal systemd unit. Stop the unit before replacing the binary; the SQLite
state directory is separate from the release binary, so rollback means
restoring the prior binary and starting the same state directory.

## Optional WhatsApp drivers

WhatsApp Cloud credentials stay outside Git in owner-only (`0600`) files. The
outbound driver needs a fixed HTTPS Graph API URL, phone id, token file,
registered template, locale, and parameter count. The inbound callback is
disabled unless its complete configuration is supplied. It listens only on a
loopback address and should sit behind an operator-managed TLS proxy.

The only inbound verbs in this alpha are `status` (a fixed non-sensitive
WhatsApp template reply) and `notify` (a fixed ntfy diagnostic). Enable or
disable callbacks only from the local host:

```sh
msgriver inbound enable --socket /var/lib/msgriver/msgriver.sock
msgriver inbound disable --socket /var/lib/msgriver/msgriver.sock
```

## Verification

The hermetic suite uses loopback provider fakes and never contacts public
services:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Live WhatsApp delivery additionally requires an operator-provisioned Meta app,
approved template, sender, test recipient, callback proxy, and secret files.
No credential is included in this repository.

## Contributing and security

MsgRiver is MIT licensed and uses the Developer Certificate of Origin.
Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[GOVERNANCE.md](GOVERNANCE.md) before contributing or reporting a vulnerability.
