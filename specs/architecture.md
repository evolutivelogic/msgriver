# MsgRiver architecture and interface specification

| Field | Value |
|---|---|
| Document status | Blocker-closure revision |
| Architecture version | 0.3.62 |
| Product contract | `specs/product.md` 0.3.46 |
| Updated | 2026-09-19 |
| Owner | Evolutive Logic |

This is the living technical contract for the first MsgRiver slice. It selects one implementation for
the observable product requirements; it does not weaken them. Stable `A-*` and `INV-*` identifiers
make design choices, tests, and review findings traceable.

## A-00. Decision frame

### A-00.1. Selected shape

MsgRiver is a modular monolith distributed as one Rust binary: one server process, one local SQLite
database, compiled-in drivers, one primary Unix-domain API listener, and optional authenticated TCP.
The same binary contains an API-only CLI client behind a separate crate boundary. It deliberately
avoids a broker, database daemon, plugin runtime, scripting engine, control-plane UI, and multi-node
coordination.

### A-00.2. Non-negotiable invariants

- **INV-001 — Durable acknowledgement.** A fresh `201` leaves the process only after the enqueue and
  idempotency transaction commits under SQLite WAL with `synchronous=FULL`.
- **INV-002 — One state owner.** Exactly one daemon owns the writable state directory and database.
- **INV-003 — One mutation path.** All selected SQLite/product-state mutations pass through one store
  actor and explicit transactions. Fixed-root transition/journal mutations pass only through the
  lock-owning control coordinator and A-13.2/A-14.3 barriers. CLI clients never open the live database,
  state directory, operational configuration, or service key rings.
- **INV-004 — Fenced effects.** A worker starts and commits under one lease fence; stale evidence can
  never roll state backward.
- **INV-005 — Honest uncertainty.** Possible external effect and possible duplicate flags are sticky.
- **INV-006 — Stable identity.** Principals outlive peer sessions and API-key rotation.
- **INV-007 — Fixed egress.** A client can select only an authorized registered provider and typed
  values; it cannot change endpoint, method, headers, authentication, proxy, or trust roots.
- **INV-008 — No sensitive diagnostics.** Content, destination, caller idempotency/correlation values,
  fingerprints, secrets, provider bodies, and private provider configuration never enter logs,
  metrics, argv, or errors. Generated non-secret resource IDs are allowed evidence, never capabilities.
- **INV-009 — Bounded work.** Every ingress body, queue share, channel, timeout, retry, response, list,
  backup step, and shutdown wait is bounded.
- **INV-010 — Hermetic gate.** The standard test suite cannot reach a public network.
- **INV-011 — Explicit support.** Only ntfy is first-slice provider support; generic HTTP/webhook and
  every other roadmap driver remain rejected as unsupported configuration until their own gate closes.
- **INV-012 — Interface parity.** Every product capability is one frozen operation in
  `specs/operations.toml`, invoked through both versioned API and CLI with identical semantics. Router,
  authorization, client, CLI, and docs prove exact set equality; CLI code never calls server/store
  internals.

### A-00.3. Primary trade-offs

| Decision | Benefit | Accepted cost |
|---|---|---|
| SQLite WAL + one writer | Self-contained durable queue and simple recovery | Single-node ceiling and serialized mutations |
| `synchronous=FULL` | Power-loss durability on honest storage | Higher enqueue latency; batching may not acknowledge early |
| HTTP-shaped protocol over Unix socket | One contract for CLI and applications | Custom Unix client/listener plumbing |
| Compiled-in drivers | Auditable dependency and egress surface | A new driver requires a release |
| Stable principals + rotatable keys | Correct ownership/idempotency | More lifecycle code in slice one |
| Pinned provider identity generation | No silent rerouting | Old generations must remain operable or visibly held |
| Logical purge claim only | Honest SQLite/backup boundary | No forensic-erasure promise |
| Validated restart | Small configuration state space | Brief admission interruption |

## A-01. Runtime topology and trust boundaries

```text
                  operator-owned host / service boundary

 Unix client --+       +------------ MsgRiver normal ------------+
               | UDS   | auth -> typed operation -> store actor   |
 TCP client ---+------>| API/CLI parity       |                   |
 (API key)             |                      v                   |
                       | scheduler -> fenced workers -> drivers --+--> provider
 operator API -------->|       ^              |                   |    endpoint
 protected secrets --->|       +--- SQLite <--+                   |
                       +-------------------------------------------+
                                   ^ mutually exclusive state lock
 state owner ------UDS----> MsgRiver maintenance (no TCP/egress/workers)
                                   |
                              restore/bootstrap
```

### A-01.1. Trust zones

| Zone | Trusted for | Never trusted for |
|---|---|---|
| Unix socket filesystem gate | Reaching authentication middleware | Principal identity or operator scope by itself |
| Peer-credential mapping | Configured UID→principal/scopes mapping | Caller headers or process display name |
| API key | Bound principal/scopes after verifier match | Endpoint choice or payload safety |
| Operator config | Provider endpoint/policy and non-secret mappings | Secret values or unchecked template execution |
| Protected secret file/credential descriptor | Runtime secret injection | Logging, catalog, backup manifest, environment, or API output |
| SQLite state | Durable application truth after integrity checks | Executable code or unbounded provider response data |
| Provider | Its own bounded protocol response | Redirect target, response body, retry hint, or receipt truth beyond the driver contract |
| Trusted TLS reverse proxy | Transport protection and source binding | MsgRiver authorization; API keys remain mandatory |
| Backup artifact | Point-in-time state within manifest watermark | Current purge state or proof an external effect did not occur later |

### A-01.2. Deployment bindings

- Primary API: `/run/msgriver/msgriver.sock`, owner `msgriver`, group `msgriver-clients`, mode `0660`.
- Maintenance API: `/run/msgriver-maintenance/msgriver.sock`, owner `root`, mode `0600`; its only
  accepted client peer in the first slice is UID 0. It is present only while the normal daemon is
  stopped and the maintenance process owns the state lock.
- Optional TCP API: disabled by default; Sol binds `127.0.0.1:8098` and remains API-key authenticated.
- Probes: versioned UDS operations plus systemd `READY=1`/watchdog. There is no unauthenticated or
  dedicated TCP probe listener; every normal TCP request authenticates.
- Metrics: Unix/operator surface only in slice one.
- Fixed ownership root: `/srv/msgriver/data/`, containing `msgriver.lock`, a checksummed atomic
  `active-state` pointer, one owner-only mode-`0700` `generations` directory containing complete final
  state-generation directories named `g-` plus their final-generation's sixteen lowercase hexadecimal digits,
  the fixed control journal, and the separately escrowed recovery-key ring, all owner-only. Only the selected
  generation's SQLite files mutate during normal operation; once deselected, a generation is sealed
  and never modified again.
- Operational non-secret config: versioned inside the active state generation and changed only through
  API/CLI. `/etc/msgriver/bootstrap.toml` is a minimal root-owned envelope for paths, credential roots,
  and systemd-provided listener names; it contains no provider, policy, principal, grant, or mapping.
- Runtime secret file: `/etc/msgriver/providers.env`, `root:msgriver`, mode `0640`, materialized from
  SOPS by deployment tooling; the portable binary has no SOPS dependency.

## A-02. Rust workspace and dependency direction

### A-02.1. Workspace layout

```text
Cargo.toml
crates/
  msgriver-core/        pure domain values, validation, state machine, policy math
  msgriver-protocol/    frozen operations, wire codecs, API error and parity metadata
  msgriver-store/       SQLite schema, migrations, transactions, store actor
  msgriver-sqlite-sealing-adapter/  [PENDENTE: Task0146/0147] future descriptor-bound SQLite sealing boundary
  msgriver-connectors/  driver boundary, exact HTTP policy, fake and ntfy drivers
  msgriver-client/      API transports and CLI dispatch; structurally unable to reach store
  msgriver/             server/auth/scheduler plus binary composition and presentation
```

Dependency direction is one-way:

```text
                    msgriver-core
                  ^       ^      ^
                  |       |      |
           protocol     store  connectors
              ^           ^       ^
              |            \     /
            client -------- msgriver
```

- `msgriver-core` has no Tokio, HTTP, SQLite, filesystem, process, or platform dependency.
- `msgriver-store` is synchronous and has no Tokio, Axum, HTTP, or provider dependency.
- `msgriver-protocol` embeds/parses `specs/operations.toml` and owns wire-only types; it has no store,
  filesystem, provider, or server dependency.
- `msgriver-connectors` may use Tokio/Hyper/Rustls but cannot depend on store or application code.
- `msgriver-client` depends only on protocol plus client transport/presentation support. Cargo metadata
  and compile-fail tests reject any transitive path to `rusqlite` or `msgriver-store`.
- `msgriver` is the only server composition root and the only crate that knows store actors, listeners,
  scheduler, commands, and operating-system integration.
- Every library crate starts with `//!` mental-model documentation and `#![forbid(unsafe_code)]`. The future sealing adapter remains [PENDENTE: Task0146/0147] and creates no unsafe exception until source-first reentry.
- Structural tests inspect manifests and dependency metadata to enforce this graph.

The fixed-root resource-incarnation / branch allocator's decision math is pure and is assigned to
`msgriver-core`; its durable effects stay in the journal coordinator (INV-003). Each of the following
pure functions MUST live in `msgriver-core` with exactly the signature and frozen behavior shown:

| Core-owned function | Signature (pure) | Frozen behavior |
|---|---|---|
| `derive_owner_namespace` | `(&dyn JournalNamespaceProvider) -> OwnerNamespace` | the provider MUST expose exactly `derive_resource_incarnation_namespace_v1() -> [u8; 24]` implementing `Truncate192(HMAC-SHA-256(journal_key, "msgriver/resource-incarnation-namespace/v1"))`; it MUST NOT be a general MAC oracle, MUST NOT synthesize a `MacKeyId`, and the journal key MUST NOT enter core |
| `compose_incarnation` | `(OwnerNamespace, BranchSerial) -> ResourceIncarnation` | MUST yield `NS[24] || U64BE(serial)` with nonzero serial |
| `encode_incarnation_hex` | `ResourceIncarnation -> 64 lowercase hex` | MUST emit exactly 64 lowercase hexadecimal characters and MUST round-trip byte-exact through its decoder |
| `decode_incarnation_hex` | `64 lowercase hex -> ResourceIncarnation` | MUST reject uppercase, wrong width, or non-hex and round-trip byte-exact with its encoder |
| `next_branch_serial` | `(high_water: u64) -> Result<BranchSerial, IncarnationUnavailable>` | MUST use checked `+1`, MUST NOT issue zero, and MUST return `state_incarnation_unavailable` at `u64::MAX` without wrap; both 32-bit storage-limb carry seams are exercised |
| `classify_transition` | `(OperationId) -> Allocating \| Continuation \| NonAllocator` | `Allocating` MUST be exactly `{bootstrap.create, restore.create, upgrade.rollback}` and `Continuation` MUST be exactly `{configuration.activate, state_key.rotate, state_key.retire, upgrade.migrate, upgrade.activate, forward_repair}`; any unlisted operation MUST be `NonAllocator`, and an unlisted operation claiming either role MUST be a compile-time exhaustiveness failure |
| `classify_witness` | `(epoch, recomputed_ns, high_water) -> LocalWitness \| ForeignAncestry \| Corrupt` | MUST apply A-10.2 rules 18–19 including the "current root's immediate boundary" scoping and R3-INV-109's `imported_key_origin` exclusion |
| `validate_target` | `(target, WitnessSet) -> Ok \| Collision \| SourceMismatch \| TargetSerialMismatch` | MUST be bounded, nonmutating, and identical on retry |
| `allocator_hold_precedence` | `(request, HoldSet, AllocatorState, ClockState, CapacityState) -> Decision` | MUST apply the total precedence order: exact same-command recovery → forbidding restore/upgrade hold → nonmutating allocator validation → `clock_hold` → `control_capacity` → admission/drain/coordinator conflict → publish-and-burn (A-10.2 rules 16–17) |
| `readiness_reason` | `(high_water, guarded_generations) -> ReasonSet` | MUST derive only the pure exhaustion subset `{generation_exhausted, incarnation_exhausted}` and its precedence from the supplied persisted branch high-water and guarded generations; `incarnation_exhausted` holds at `u64::MAX`, and when both reasons are present it takes precedence. It performs no I/O and owns no presentation, prose, structured field, or enumerated label; A-15.3 owns assembly of the complete closed set |

Explicitly not core: the durable burn, the authenticated image replacement, the fsync/rename barriers,
and pointer publication. Core returns a decision; the journal coordinator performs exactly one atomic
publication.

### A-02.2. Toolchain and package policy

- Edition: Rust 2024.
- First published Cargo package version: `0.1.0-alpha`; the first public release uses an annotated Git
  tag whose exact name is also `0.1.0-alpha` on a clean reviewed commit.
- MSRV: Rust 1.89, required for the standard-library file-lock API.
- Pinned development/release toolchain: Rust 1.96.1; bumps are isolated and tested green before/after.
- License metadata: Apache-2.0; packages publish only when release metadata is complete.
- `Cargo.lock` is committed; every gate and release command uses `--locked`.
- Release profile enables overflow checks and strips no evidence needed for supported diagnostics.
- Direct dependency additions require a written rationale and `cargo deny` license/advisory/source
  review; registry crates only, no git dependencies.

### A-02.3. Initial dependency budget

| Dependency family | Purpose | Boundary/rationale |
|---|---|---|
| `serde`, `serde_json`, `toml` | Wire/config encoding | Closed structs use `deny_unknown_fields` |
| `thiserror`, `anyhow` | Typed library errors / binary context | `anyhow` only at composition/CLI boundary |
| `rusqlite` with `bundled`, `backup` | Embedded SQLite and online backup | Bundled SQLite must be >= 3.51.3; no system drift |
| `tokio`, `axum`, `tower` | Async listeners, middleware, scheduling | Server composition only |
| `hyper`, `hyper-util`, `http-body-util`, `tokio-rustls`, `rustls` | Exact one-attempt HTTP/1 client | Connector crate only; no redirects, proxy, decompression, HTTP/2, cookies, or implicit retry |
| `clap` | CLI parsing | No sensitive value flags |
| `uuid` | UUIDv7 generated IDs | Generator seam makes tests deterministic |
| `hmac`, `sha2`, `subtle`, `rand` | Key verification, domain-separated MACs, secrets | No password hashing for 256-bit random API keys |
| `chacha20poly1305`, `hkdf` | Encrypt state-key sections under recovery keys | XChaCha20-Poly1305 with domain-separated derived keys |
| `secrecy`, `zeroize` | Redacted/cleared in-memory secret wrappers | Secret bytes never implement display/debug serialization |
| `url` | Operator URL parsing/canonicalization | Never parses caller-provided endpoints |
| `tracing`, `tracing-subscriber` | Structured redacted telemetry | Field allowlist, no arbitrary value recording |
| `prometheus-client` | Bounded local metrics exposition | Static label enums only |
| `crossbeam-channel` | Prioritized synchronous store actor mailboxes | Keeps Rusqlite off async workers |
| `rustix` | Safe Unix peer, file, directory-sync, and socket operations | Platform adapter only; production remains unsafe-free |

Tests may add `tempfile`, `proptest`, `assert_cmd`, and loopback HTTP helpers. Any larger dependency
must replace more risk than it adds; a general template engine, JSONPath engine, plugin loader, or ORM
is explicitly excluded.

## A-03. Execution and concurrency model

### A-03.1. Process components

| Component | Execution context | Responsibility |
|---|---|---|
| Listener supervisor | Tokio tasks | Accept UDS/TCP/probe connections and attach transport identity |
| API middleware/handlers | Tokio tasks | Bounds, auth, authorization, wire mapping, response deadlines |
| Store actor | One dedicated OS thread | Own one read/write SQLite connection and all mutations |
| Read service | Bounded pool of 2–4 read-only WAL connections | Status/list/catalog/health snapshots; no mutation or unbounded transaction |
| Scheduler | One Tokio task | Request fair claims while worker/provider slots exist |
| Delivery workers | Bounded Tokio task set | Invoke one connector call and return typed outcome/evidence |
| Maintenance loop | Tokio timer + store commands | Purge, idempotency expiry, checkpoints, circuit probes, disk checks |
| Clock guard | One Tokio task | Compare wall and monotonic deltas and establish anomaly hold |
| Shutdown coordinator | One Tokio task | Stop admission, bound workers, preserve in-flight leases, checkpoint |

The table describes normal mode. Maintenance mode runs only the listener supervisor, strict
state-owner peer authentication, bounded API handlers, the restore/bootstrap coordinator, and a
fixed-root clock guard using the same injected wall/monotonic clocks. It has
no TCP listener, scheduler, delivery worker, provider client, proxy, metrics listener, or ambient
network permission.

### A-03.2. Store actor mailboxes

The actor owns four bounded channels:

1. `critical`: authentication freshness/revocation epochs, existing-idempotency lookup/recheck, outcome
   commit, clock/storage hold, backup page step, and shutdown safety;
2. `control`: authorization mutations, cancel, purge, admission control, audit, and bounded maintenance;
3. `admission`: validate-current provider, atomically recheck idempotency, quota, and enqueue;
4. `delivery`: claim, dispatch mark, outcome preparation, retry/circuit, expiry, and retention.

Each loop drains a bounded critical/control burst, then services up to three delivery commands for one
admission command while both are backlogged, and rechecks critical/control between every command.
Empty classes are skipped. This covers the three durable delivery phases without allowing admission to
starve already accepted effects or terminal evidence. Channel capacities and request semaphores are
part of configuration; a full admission mailbox returns `429`, while loss of critical reserve returns a
loud bounded `503` and degrades readiness.

After A-05 identity authentication, submit computes the canonical lookup digest in that exact principal
namespace and uses a dedicated reserved critical pre-pass. A hit satisfying A-07.4's enabled-owner rule
returns the existing result/conflict without consuming admission quota or mailbox. A miss enters
the admission mailbox, whose transaction repeats the same lookup before creation. Saturation therefore
cannot block response-loss recovery, and the race between pre-pass miss and concurrent commit still
creates at most one command. Ordinary read operations use the bounded WAL read pool; authorization,
idempotency, outcomes, and any read requiring mutation-linearizable freshness stay on the actor.

Tokio handlers use non-blocking `try_send` into crossbeam mailboxes and await a Tokio one-shot; they
never call blocking send/receive on a runtime worker. Every mutation envelope contains one shared atomic
lifecycle token with only `queued -> cancelled` or `queued -> started -> committed|failed` transitions.
At the pre-start deadline the handler may CAS `queued -> cancelled`; only that successful CAS permits a
definite `408`, and the actor must observe/drop the cancelled envelope without touching state. If the CAS
observes `started`, the handler waits through a separately bounded store-commit margin. A lost receiver
never cancels started work. If delivery of the authoritative result cannot complete within that margin,
the handler returns `503 operation_outcome_unknown`, which makes no commit claim and directs recovery
through the same command/domain key or the operation's idempotent status surface. The actor never
executes provider I/O or waits on an async task. Dropping a client response after commit does not roll
back the command. Queue/start/commit/receiver races are explicit typed results and loom/process stress
tests; configuration proves the actor's transaction/busy bound fits inside the post-start margin.

### A-03.3. Single-owner lock

Before resolving the active generation or opening SQLite, the daemon opens the fixed parent
`/srv/msgriver/data/msgriver.lock` with `create_new`-safe permissions and acquires
the standard-library non-blocking exclusive file lock. It keeps that exact file handle alive for the
process lifetime. The lock is outside every swappable state generation. The normal-startup caller then validates the
host-keyed HMAC `active-state` pointer certificate (generation, lineage, history epoch, origin
transition, protocol version) and opens only the named complete generation whose SQLite meta mirrors
that certificate digest; if generations exist but no valid pointer does, normal startup fails closed.
This startup selection consumes no `PointerRenamed` and cannot terminalize a transition. A-14.3's
retained post-rename `PointerRenamed` carries only an opaque borrowed view of the already-retained
operational root and may enter exactly one private non-Clone pre-terminal coordinator with the authenticated
pointer; no supplied name, descriptor, root, scan or pointer reread can substitute. That coordinator alone
derives a private non-Clone pointer-named generation handle from the authenticated nonzero final generation,
bound to that retained root and carrying the pointer certificate digest only into its exact selected
SQLite-meta equality obligation. The handle and its nonterminal comparison fact grant no selection, journal,
cleanup or response authority. The canonical `generations` child is current-euid mode `0700`; a final
generation basename is exactly `g-` plus the authenticated nonzero final generation as sixteen lowercase
ASCII hexadecimal digits. The handle may reopen only that candidate through retained descriptor-relative
`O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` opens and descriptor-local `fstat` checks; it neither selects nor
claims it complete. Only the coordinator-borrowed candidate may open `state.sqlite3` relative to itself with `O_RDONLY`, `O_NOFOLLOW`, and `O_CLOEXEC`; fstat requires a current-euid-owned mode-`0600` single-link regular file. Its same-descriptor private sealed-image observation establishes checkpoint/close after the pointer mirror write and that WAL/SHM cannot alter the read-only view. The exact singleton-meta equality fact is private and nonterminal, never selection or completeness. The future internal sealing adapter is [PENDENTE: Task0146/0147 pointer-authenticator ownership]; no crate, FFI/VFS implementation, sealing RED, selected-meta comparison, or root-side substitute is authorized until its source-first reentry condition closes. The caller additionally requires bound
transition evidence before it can form the separate
nonterminal validation receipt. Maintenance may resume only a checksummed
fixed-root control-journal transition for bootstrap or blank-state restore with the same command/body
digest; it never guesses from unrelated generation names. Prior-process shutdown entries reconcile
without selecting a generation. Failure is fatal before migration or readiness. SQLite
state on a network filesystem is rejected by deployment documentation and startup filesystem checks
where reliable; WAL is a same-host design.

The private `active-state-pointer/v1` certificate is exactly `U8(1) ||
U32BE(protocol_version) || LP16BE(transition_id UTF-8) ||
U64BE(final_generation) || LP16BE(lineage_id UTF-8) ||
ResourceIncarnation[32] || U8(origin) || database_certificate_digest[32] ||
HMAC-SHA-256(journal_integrity_key, ASCII("msgriver/active-state-pointer/v1")
|| every preceding byte)`. Transition and lineage IDs are nonempty no-NUL
UTF-8 of at most 255 bytes. Origin codes are exactly `1=bootstrap`,
`2=restore`, and `3=rollback`; generation and certificate digest are nonzero.
Its exact total is `114 + transition_length + lineage_length` bytes, hence
116..=624. Decoding uses only bounds reads before authentication: at least 7
bytes before `transition_length`, `1..=255`, at least `17 + transition_length`
before `lineage_length`, `1..=255`, then the exact total. It verifies the HMAC
in constant time before format, UTF-8, origin, or nonzero validation and before
returning a field. This is a private value codec only; A-14.3 still solely owns
its pathname, temp/rename/fsync publication, reopening, selection, and recovery.

The maintenance process acquires the same lock before exposing bootstrap or restore and therefore
requires the normal daemon stopped. Those operations still cross the local versioned API; their
handlers never coexist with delivery workers. No stale lock file deletion is needed: the operating
system releases the lock when the owner exits.

## A-04. Domain model and injected seams

### A-04.1. Core values

The core crate uses validated newtypes rather than raw strings/integers:

- `MessageId`, `AttemptId`, `RequestId`: UUIDv7 bytes with canonical lowercase text at the wire;
- `PrincipalId`, `ProviderId`, `ConnectorIdentityId`: ASCII identifiers with separate grammars;
- `IdempotencyKey`, `CorrelationId`, `ReplayRequestKey`: sensitive validated 1–128 byte identifiers;
- `ResourceIncarnation`: the non-secret, non-authorizing selected authenticated structured 256-bit
  history epoch—192-bit owner namespace plus 64-bit big-endian branch serial—with canonical lowercase
  64-hex wire encoding; `GuardedGeneration`: a checked nonzero `u64` represented in SQLite as two
  unsigned 32-bit limbs rather than an out-of-range signed integer;
- MAC key identity values: `OriginIncarnation` is the 32-byte authenticated allocator origin
  `OwnerNamespace[24] || U64BE(branch_serial)`, reused unchanged from A-10.2's fixed-root allocator so
  sibling branches always carry distinct origins. `MacKeyId` is the fixed-width 40-byte value
  `OriginIncarnation[32] || U64BE(purpose_local_serial)`; `purpose_local_serial` is a nonzero `u64`,
  monotone per `(OriginIncarnation, MacPurpose)`, never a counter that decrements or reclaims. `MacPurpose`
  is the closed first-slice `u8` enum of A-04.2. `MacKeyRef` is the resolvable pair
  `(MacPurpose, MacKeyId)`; because the serial is purpose-local, `MacKeyId` alone is not a globally
  resolvable identity, so every lookup, equality check, artifact row, and storage path uses `MacKeyRef`.
  `PreBootstrapOrigin` is the reserved origin `OwnerNamespace[24] || U64BE(0)`, never allocated because
  allocator rule 7 never issues serial zero, and used only by the fixed-root portable-reservation key
  created before any branch exists. Canonical `MacKeyId` wire/text form is exactly 80 lowercase
  hexadecimal characters; uppercase, short, long, or non-hex spellings are rejected. A MAC key identity
  is a structured, branch-safe, immutable value and is explicitly not a `GuardedGeneration`: a
  `GuardedGeneration` is reset to `(0,1)` on restore/rollback, whereas MAC generations survive branching
  and artifact closure (A-13.2, A-14.1), so the two lifecycles are incompatible;
- `UtcMillis`, `MonotonicTick`, `DurationMillis`: checked arithmetic, never raw system clocks;
- `FenceToken`: random 128-bit value plus monotonic lease generation;
- `SensitiveText`, `DestinationValue`, `ApiSecret`, `ProviderSecret`: redacted `Debug`/`Display`;
- closed enums for state, hold reason, outcome/error class, scope, driver kind, support level, and
  availability.

No domain transition accepts wall-clock reads, random generation, or I/O implicitly. Interfaces inject:

- `Clock` (`utc_now`, monotonic sample);
- `IdGenerator`;
- `MacProvider` with purpose and `MacKeyId`;
- deterministic `JitterSource`;
- `DiskBudgetProbe` at the application/store boundary;
- driver outcome values rather than raw HTTP responses.

### A-04.2. Semantic canonicalization

Idempotency fingerprint version 1 is not canonical JSON. After strict decoding and validation, core
encodes the semantic request in the fixed-order byte sequence whose framing is frozen as the executable
E1 codec. With `U8(v)` a single unsigned byte, `U32BE` and `I64BE` big-endian fixed-width integers,
`LP32(x) = U32BE(length(x)) || x`, and the optional tag `OPT(absent) = 00` / `OPT(present x) = 01 || x`:

```text
ROLE_DESTINATION = U8(1)
ROLE_CONTENT     = U8(2)
ROLE_OPTIONS     = U8(3)
SEG(role, schema_id, kind, schema_version, payload) =
    role || LP32(UTF8(schema_id)) || LP32(ASCII(kind)) ||
    U32BE(schema_version) || LP32(payload)

REQUEST_V1 =
    "msgriver-request\0" || U32BE(1) || LP32(provider ASCII) ||
    SEG(ROLE_DESTINATION, destination tuple, destination payload) ||
    SEG(ROLE_CONTENT, content tuple, content payload) ||
    OPT(SEG(ROLE_OPTIONS, options tuple, options payload)) ||
    OPT(I64BE(expires_at UTC milliseconds)) ||
    OPT(LP32(correlation_id ASCII))
```

Each segment carries its exact `(schema_id, kind, schema_version)` schema-registry tuple as the `SEG`
identity and the role's normalized payload bytes as the `SEG` payload. `schema_version` is a fixed-width
`U32BE`, not length-prefixed, so framing stays unambiguous. An absent optional is its `00` tag and a
present optional is `01 || value`; explicit null is invalid. The first-slice tuple and payload codecs are
exactly:

- destination = (`msgriver://schema/ntfy-topic/1`, `ntfy_topic`, version 1), payload `LP32(topic ASCII)`;
- content = (`msgriver://schema/text/1`, `text`, version 1), payload
  `OPT(LP32(title UTF-8)) || LP32(nonempty text UTF-8)`;
- options = (`msgriver://schema/ntfy-options/1`, `ntfy`, version 1), payload
  `LP32(priority ASCII) || U32BE(tag_count) || each LP32(tag ASCII)` in canonical unsigned-byte order.

Each role is a distinct schema; destination, content, and options are not a collective `text/1` codec.
Omitted title is `00`; present title is `01 || LP32(title)`. Ntfy options always normalize to a present
options segment (`01 || SEG(...)`), including omitted options and the explicit default object, so the
first-slice options `OPT` is always present; expiry and correlation use their own `OPT` tags and may be
absent. No connector configuration, operator setting, or catalog value participates in default expansion,
because defaults are immutable properties of the named schema version. JSON member order and insignificant
wire formatting disappear; text bytes, null/absent distinctions defined by the schema, and every
client-semantic field remain. Defaults are expanded before encoding; set-like values such as ntfy tags are
validated, deduplicated, and sorted by canonical unsigned-byte order, so omitted default options and
permuted tags compare equal. Private mutable connector identity/generation, credential generation,
authorization grant, and current config are deliberately excluded: they govern fresh admission and
pinning but are not part of what the caller requested. Raw canonical bytes are not persisted after use.

The framing of the canonicalization-version-1 vector is frozen as a known answer. The minimal ntfy
submit encodes to exactly `REQUEST_V1_LEN = 222` bytes:

```text
REQUEST_V1_HEX =
  6d736772697665722d726571756573740000000001000000046e746679010000001e
  6d736772697665723a2f2f736368656d612f6e7466792d746f7069632f310000000a
  6e7466795f746f706963000000010000000a00000006616c6572747302000000186d
  736772697665723a2f2f736368656d612f746578742f310000000474657874000000
  010000000a000000000568656c6c6f0103000000206d736772697665723a2f2f7363
  68656d612f6e7466792d6f7074696f6e732f31000000046e74667900000001000000
  0f0000000764656661756c74000000000000
REQUEST_V1_SHA256 = d9d07401c9f6338a4cdbf4f7b41c19780addc016d6f707c553bb2101dfb31ac3
```

The maximum first-slice encoding is 5,119 bytes (21 preamble + 68 provider + 125 destination + 4,406
content + 357 options + 9 expiry + 133 correlation); the widest non-ntfy `text/1` command remains below
the 65,536-byte first-slice cap, which rejects an over-large submit before encoding.

The lookup digest for `(principal, idempotency_key)` is a different domain-separated MAC. The closed
first-slice `MacPurpose` byte enum is:

| Byte | `MacPurpose` |
|---:|---|
| `01` | `ApiKeyVerifyV1` |
| `02` | `IdempotencyLookupV1` (`LookupV1`) |
| `03` | `IdempotencyFingerprintV1` (`FingerprintV1`) |
| `04` | `ReplayLookupV1` |
| `05` | `ReplayFingerprintV1` |
| `06` | `CommandLookupV1` |
| `07` | `CommandSemanticFingerprintV1` |
| `08` | `CommandPhaseFingerprintV1` |
| `09` | `RetryJitterV1` |
| `0a` | `ArtifactInternalAuthV1` |
| `0b` | `PortableReservationV1` |

Every other byte is unknown and fails before lookup, path construction, artifact acceptance, or
high-water parsing. The two idempotency purposes are named `LookupV1` and `FingerprintV1` only as
shorthand for those two idempotency values; they are not reusable generic purposes. A purpose-qualified
key path uses the two lowercase hexadecimal digits in this table and never derives a code from display
text or enum order. Each purpose owns an independent ring slice and domain-separated construction.

The authenticated MAC construction is fixed. `FINGERPRINT_DOMAIN` is
`6d736772697665722d6964656d706f74656e63792d66696e6765727072696e742d763100` and `LOOKUP_DOMAIN` is
`6d736772697665722d6964656d706f74656e63792d6c6f6f6b75702d763100`, both NUL-terminated and prefix-free.
`MacKeyId` is fixed-width 40 bytes with no length prefix, so framing stays unambiguous:

```text
fingerprint_tag = HMAC-SHA-256(K_fp,
    FINGERPRINT_DOMAIN || MacKeyId_fp[40] || LP32(REQUEST_V1_bytes))

lookup_digest   = HMAC-SHA-256(K_lk,
    LOOKUP_DOMAIN || MacKeyId_lk[40] ||
    LP32(canonical principal-ID ASCII) || LP32(validated idempotency-key bytes))
```

The revision-3 MAC vector is frozen as a known answer. With
`OwnerNamespace = a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7`, `branch_serial = 42`, and
`purpose_local_serial = 7`, the `MacKeyId` is
`a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7000000000000002a0000000000000007`; under
`K_fp = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
`K_lk = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`,
`principal_id = principal-1`, and `idempotency_key = request-1`, the constructions yield
`fingerprint_tag = 0f53ea3942cc0a3844cfcb6d1c6e70a67332dbca1681369ec38fa867d4a43988` and
`lookup_digest = 0a81d319e0d706a7ac0f0db3aa062f3f4e81f4ab18e577f144d1d153215eb989`. The owner-namespace
allocator KAT is frozen from the same boundary: journal-key bytes `00` through `1f` and the exact ASCII
label `msgriver/resource-incarnation-namespace/v1` give full HMAC-SHA-256
`1c49798de4fdd848714c7dc610350ebb66ae5ee815275fbe5865f2ded712f389`, whose `Truncate192` is
`1c49798de4fdd848714c7dc610350ebb66ae5ee815275fbe`. These expected values are literals fixed before the
executable models; they are never regenerated as their own expectations. A reviewer reproduces them with a
third-party pipeline: `printf '%s' "$HEX" | xxd -r -p | openssl dgst -sha256` for the request digest and
`openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY` for the MAC constructions, where the fingerprint
message is `FINGERPRINT_DOMAIN || MacKeyId || 000000de || REQUEST_V1_HEX`, the lookup message is
`LOOKUP_DOMAIN || MacKeyId || 0000000b || hex("principal-1") || 00000009 || hex("request-1")`, and the
allocator recipe pipes the exact ASCII label directly to HMAC under the journal key.

The two domains are not reused for API-key verification, replay, operation commands, portable
reservations, or jitter; each has its own closed purpose and ring slice. The service computes the
fingerprint MAC under the active `FingerprintV1` key and persists that row's `MacKeyId` plus the 32-byte
tag; the lookup MAC under the active `LookupV1` key is persisted the same way. A `VersionedTag` is the
triple `{ purpose: closed MacPurpose, key_id: MacKeyId, tag: [u8; 32] }`; `MacProvider` resolves by
`(MacPurpose, MacKeyId)` and returns it, and raw key bytes never cross, format through, or become
debuggable by core. Constant-time comparison applies to exactly the 32 tag bytes, only after public
`MacKeyRef` equality; cross-purpose or cross-key equality is never evaluated, and the comparison result
is exactly the authentication result—performing the comparison and discarding its result is an
authentication failure.

The dispatch of an existing idempotency row is frozen. The incoming request is always decoded and
validated under the schema tuples it declares; the matched row's schema tuples are never substituted, and
the row's defaults are never applied to different incoming schemas. The matched row's persisted
canonicalization version is the only thing that frames comparison: it selects the `REQUEST_V1` framing,
not the payload semantics. At the reserved pre-pass, after A-05 authentication and bounded strict
decoding, processing is, in order: strict validation of the incoming command against its declared
`(kind, schema_version)` codecs, so an unknown or unsupported declared tuple returns `422` before any
lookup or store command; lookup over the retained lookup-key ring; the expiry gate, where a row whose
half-open boundary is at or below PR-149's effective durable authenticated high-water is proven-expired
and is never again a candidate; the tuple-inequality short-circuit, where if any of the three persisted
`(role, schema_id, schema_version)` triples differs from the incoming declared triple the service returns
`409 idempotency_conflict` without encoding anything—exactly equivalent to comparing tags because the
triples are inside the fingerprint segment, removing the cross-version encodability problem and making it
structurally impossible for an old row to pull a newer tuple through old defaults; and finally encode and
compare, where otherwise the incoming already-validated request is encoded under the row's
canonicalization version and the identical declared codecs and the 32 fingerprint bytes are constant-time
compared under the row's fingerprint `MacKeyId`. The outcome table is closed:

| Case | Condition | Outcome |
|---|---|---|
| D-1 | Same tuples, equal tags | `200`, `deduplicated = true`, original `message_id`/state/`idempotency_expires_at` (PR-072) |
| D-2 | Same tuples, unequal tags | `409 idempotency_conflict`; original command preserved (PR-073) |
| D-3 | Any tuple differs, both sides valid and retained | `409 idempotency_conflict` via short-circuit; no encoding, no default expansion |
| D-4 | Incoming declared tuple unknown/unsupported by this binary | `422` at strict validation, before lookup |
| D-5 | Row's canonicalization version or a row-referenced schema codec is unavailable in this binary | `503 canonicalizer_unavailable`, readiness reason `idempotency_codec_unavailable`; never fall back to the active version. Startup and restore have already failed closed, so this is a corruption path, not a routine one |
| D-6 | Row corrupt: absent version, unknown/unparsable `MacKeyId`, tag length ≠ 32, undecodable persisted tuple, or tuple/`kind` disagreement | `503 idempotency_evidence_corrupt`; no dedupe, no conflict, no creation; audit event with a closed internal subreason; readiness degraded |
| D-7 | More than one unexpired candidate across distinct retained lookup key ids | `503 idempotency_evidence_corrupt` (subreason `multiple_match`); the unique index forbids duplicates within one key id, so this can only be corruption or an unsound merge |
| D-8 | Multiple candidates where all but one are proven-expired | Proven-expired candidates are invisible; the single unexpired candidate dispatches normally |
| D-9 | Miss | Enter admission; the enqueue transaction repeats the lookup through compare steps atomically before quota and insert (A-10.4) |

`canonicalizer_unavailable` and `idempotency_evidence_corrupt` carry no caller-visible detail: no stored
fingerprint, no key id, and no schema identity beyond what the caller already declared. Metric labels
use only the closed code.

Canonicalization versions are retained and executable for at least the maximum supported idempotency
window and oldest supported backup. Lookup reads the record's version and never silently recomputes an
old command with current defaults. A release cannot retire a canonicalizer while any live or supported
restored record names it; a schema tuple is retired only when no live row, no supported artifact, and no
supported provenance closure names it, so a release that drops a codec while such a reference exists fails
the release gate rather than at runtime.

## A-05. Identity, authentication, and provider authorization

### A-05.1. Stable principals

`principals` are database records with immutable ID, mutable display name, enabled flag, quotas,
scopes, a checked non-wrapping resource generation under the selected resource incarnation, and one
fixed nullable last guarded-principal transition receipt. Every principal mutation increments that
resource generation; a guarded enable or disable atomically replaces the receipt, while a command-key
update invalidates an older receipt simply by advancing beyond its result generation. Principal
creation initializes both principal and grant-collection generations to one with null receipts under
the current incarnation. Message ownership references the principal ID. Disabling a principal blocks
new authentication and submission but does not delete or reassign its messages. The prospective selected state must always
contain at least one enabled principal with `operator` scope reached by an enabled UID-0 peer mapping
whose ceiling also contains `operator`; this irreducible local recovery path is not satisfied by an API
key, TCP credential, non-root mapping, disabled row, or scope on only one side.
`principal.update` may change display name, scopes, quota profile, and other cataloged mutable metadata,
but never the enabled flag; only the generation-guarded enable/disable operations change it. Provider-
grant membership changes only through generation-guarded put/delete.

`principal_provider_grants` is an allowlist. Each principal owns one checked non-wrapping grant-
collection generation under the selected resource incarnation and one fixed nullable last guarded-
grant transition receipt; a membership change increments the collection generation and replaces that
receipt in the same transaction. A
submitter sees and uses only provider registrations in its grants; an empty grant set means none, never
all. Operator scope can inspect all registrations but must still select an enabled provider to
submit/replay.

Principal list/show responses expose `resource_incarnation` plus the safe principal resource and grant-
collection generations; grant list exposes that same incarnation and collection generation, and
admission show exposes its singleton complete pair. The corresponding CLI renderers display them. A
guarded mutation never guesses, fetches, or substitutes either address component on the caller's behalf.

### A-05.2. Unix peer authentication

The UDS acceptor captures peer UID from the accepted socket before HTTP parsing and stores it in request
extensions. Durable `peer_mappings` state maps an exact numeric UID to one existing stable principal,
enabled state, and a maximum scope ceiling. Socket group membership only permits connection; absence or
suspension of the mapping fails closed. The complete mapping lifecycle is represented in
`specs/operations.toml`. Bootstrap atomically creates the first mapping from the already authenticated
maintenance peer. In the first slice that peer is exactly UID 0 on the root-owned mode-`0600`
maintenance socket; the service account cannot authenticate as state owner merely because systemd
passed it the listening descriptor. No configuration file supplies a competing identity source.

Authorization uses one explicit algebra:

- UDS without bearer: `effective = current_principal_scopes ∩ peer_scope_ceiling`;
- UDS with bearer: malformed/invalid/revoked bearer returns `401` with no peer-only fallback; a valid
  key must name the peer-mapped principal, then
  `effective = current_principal_scopes ∩ current_key_scopes ∩ peer_scope_ceiling`;
- TCP: bearer is mandatory and `effective = current_principal_scopes ∩ current_key_scopes`.

Provider grants and operation transport policy are additional AND conditions, never scope expansion.
Every local-admin operation requires `operator` in the peer ceiling even when a matching operator key
is present; a stolen remote operator key cannot administer through TCP or a non-operator Unix peer.
The store actor evaluates principal disable/scope update and peer-mapping update/delete against the
complete prospective state in the same transaction. If it would remove the final UID-0 operator path,
the transaction changes no row and returns `409 last_local_operator`. Because all mutations serialize,
two concurrent removals cannot each observe the other path. Operators replace the anchor add-first;
bootstrap and restore each create a qualifying path before their generation can be selected.

### A-05.3. API-key format and verification

An issued key is `mrk1_<key-id>_<secret>`, where key ID is a public random identifier and secret is 32
random bytes encoded base64url without padding. The database stores key ID, principal, scopes, status,
timestamps, optional expiry, the `ApiKeyVerifyV1` `MacKeyRef` whose key material computes the verifier,
and `HMAC-SHA-256(verifier_key, "msgriver-api-key\0" || key-id || secret)` resolved by that `MacKeyRef`.

Authentication flow:

1. reject absent/malformed/oversized bearer input before database work;
2. acquire one of 16 header/preclassification slots inside the outer 64-request limit, enforce the
   16-KiB/64-header/5-second bounds there, parse the public key ID, and release that slot immediately
   after classification through an authorization-epoch-bound in-memory ID index. A partial/slow header
   never enters either verifier queue; an exhausted/expired slot fails uniformly. This bounds resources
   but does not claim valid-principal latency under a distributed slow-header denial of service;
3. send unknown IDs only through a per-source invalid-auth token bucket (burst 32, refill eight per
   second), a global abuse pool (burst 256, refill 64 per second), and fixed-size keyed dummy-work shards.
   Source address remains defense-in-depth and never the sole decision because a trusted proxy may
   multiplex clients. Unknown-ID work cannot lease a known-ID verifier;
4. reserve eight verification permits for syntactically valid IDs present as enabled rows in that
   index. The scheduler has at most 64 queued public-key-ID buckets and at most eight requests per ID;
   excess distinct-ID or per-ID work receives uniform retryable authentication saturation. Buckets are
   round-robin by public key ID, and one ID globally may lease at most one reserved permit regardless of
   source count. Verifier plus durable-row/epoch recheck has a 50-ms reference service quantum. From
   completed classification, a valid different ID therefore completes within 250 ms under saturated
   unknown-ID work or a flood of one other known public ID. No latency claim applies to simultaneous
   attacks across many distinct enabled IDs. An absent ID still computes one verifier against a fixed
   dummy record before returning the same safe failure class;
5. compute and constant-time compare exactly one keyed verifier, then recheck the durable row and exact
   authorization epoch so a stale index grants no authority;
6. check key/principal enabled, key expiry, and credential transport restriction, then establish the
   authenticated stable principal and effective scope intersection; requested-operation scope and
   provider grant are separate authorization checks after identity is established;
7. apply the principal rate bucket and emit only safe auth event codes.

The secret is returned exactly once. List output shows key ID, principal, scopes, timestamps, and status.
Every credential/principal/mapping/grant mutation increments a durable authorization epoch. A request
authenticated after a revoke commit fails; a mutation handler rechecks its captured epoch and effective
authorization in the store transaction before commit. A bounded read request already authenticated
before revocation may finish, but no later request or post-revocation mutation may use a revoked
credential or disabled principal. Effect-free A-07.4 domain-key recovery by an exact authenticated
owner after submit-scope or provider-grant removal is not use of that removed authority; every fresh
effect and every command-key result still performs its cataloged authorization check. Rotation issues a
distinct key for the same principal; it never changes
ownership/idempotency. Principal enable/disable and API-key issue/rotate/revoke do not expose their
committed responses until the in-memory ID index has published that exact authorization epoch; startup
builds the index before readiness. Publication stores the complete immutable index snapshot and epoch
with release ordering before waking the response waiter. The durable-row/epoch recheck remains
authoritative if any request retained an older snapshot; a delayed older publication cannot replace a
newer epoch. For a generation-guarded principal or grant mutation, the same `BEGIN IMMEDIATE`
transaction checks the complete expected resource incarnation/generation and current receipt, applies
the prospective `last_local_operator` invariant, advances the authorization epoch and non-wrapping
generation, writes the audit event, and replaces the one fixed receipt. No response or receipt-
recovery result is observable before the exact new authorization epoch is published.

## A-06. Provider registration and catalog

### A-06.1. Operator configuration model

Provider IDs match `^[a-z][a-z0-9_-]{0,63}$`. They are public stable names such as `ops-ntfy`; clients
never see the private connector identity ID. A first-slice registration has this logical shape:

```toml
[[providers]]
id = "ops-ntfy"
display_name = "Operations notifications"
enabled = true
driver = "ntfy_v1"
connector_identity = "ntfy-local-v1"
base_url = "http://127.0.0.1:8090"
timeout_ms = 5_000
max_concurrency = 4
allowed_topics = ["obliance"]
expose_allowed_topics = true
```

The Sol registration omits `credential_ref` because its loopback ntfy currently has no authentication;
an HTTPS registration may instead name a protected file/systemd-credential reference. Host provisioning
atomically publishes a bounded canonical `SecretReferenceCatalog` containing only logical name,
reference kind, monotonically increasing generation, and document digest. It is root-owned, no-follow
opened, and contains no secret value/path/descriptor. Both modes receive one pre-opened read-only
descriptor for a metadata-only directory containing only the fixed catalog basename. After acquiring
the state-owner lock, the daemon opens that basename relative to the descriptor with no-follow checks;
normal mode separately receives uniquely named protected value descriptors whose logical names must be
a subset of that catalog, while maintenance never receives them. The host provisioner acquires the same
lock and may replace the catalog/value-descriptor set only while both runtime modes are stopped. It
fsyncs the new catalog and parent before either unit starts, so validation can reopen and verify the
current sealed inode/generation rather than rereading a stale replaced file descriptor.

Validation rejects duplicate IDs/identities, unknown fields, secret-looking inline values, endpoint
identity changes under an existing identity, invalid URL/TLS/proxy combinations, a name absent from the
current `SecretReferenceCatalog`, empty destination policy, timeout outside compiled bounds, and lease
timeout margin violations. An existing cataloged reference whose value is temporarily unavailable does
not invalidate an already active generation: the daemon starts, holds that connector, and exposes safe
remediation state. Removing a catalog name while selected configuration still references it is an
invalid host/configuration state, not credential unavailability.
An incompatible identity must get a new `connector_identity` value. Old identities remain configured
until their non-terminal work drains, or that work becomes visibly held.

Provider registrations/policies are versioned operational state changed only through local
configuration validation and maintenance activation. Provider grants, peer mappings, principal
scopes, and quotas are independently mutable database state through their local operations. Protected
provider secret values remain host-injected files/systemd credentials referenced by name; API clients
can bind only a pre-provisioned reference and can never submit a secret value or arbitrary egress
target.

### A-06.2. Catalog representation

`GET /v1/providers` is assembled from four sources:

1. enabled provider registration;
2. driver-owned static schemas and compiled limits;
3. principal-provider grant;
4. safe runtime availability (`available`, `degraded`, or `held`).

Entries are sorted by provider ID. The response includes JSON Schema Draft 2020-12 documents from a
strict supported subset: objects, required/properties, closed additional properties, strings, enums,
arrays, numeric bounds, byte-oriented length annotations, and descriptions. `$ref` is local to the
response; remote references, regexes outside compiled driver constants, and executable annotations are
forbidden. Schema constants are compiled into native drivers and snapshot-tested against their Rust
decoders.

The per-principal ETag is the base64url SHA-256 of the canonical safe catalog representation and grant
generation. It changes when the client-visible schema, limit, support, availability, or authorization
changes. It contains no keyed secret and is not an authorization token.

`path.provider_schema_id.v1` encodes the complete UTF-8 schema identifier as canonical unpadded
base64url in the single `{schema_id}` path segment. The decoder bounds encoded and decoded lengths,
rejects padding, non-url-safe alphabet, invalid UTF-8, and any spelling that does not re-encode
byte-for-byte to the received segment, then requires the decoded identifier to be one of that
principal's schemas for `{provider_id}`. The CLI accepts the catalog's full schema identifier and uses
the same client codec; clients never place the URN's literal `/` or `:` bytes into the route.

Example entry:

```json
{
  "provider_id": "ops-ntfy",
  "display_name": "Operations notifications",
  "channel": "push",
  "driver": "ntfy_v1",
  "support": "proven",
  "availability": "available",
  "destination_schema": "msgriver://schema/ntfy-topic/1",
  "content_schemas": ["msgriver://schema/text/1"],
  "options_schema": "msgriver://schema/ntfy-options/1",
  "limits": {"command_bytes": 65536, "title_bytes": 256, "text_bytes": 4096}
}
```

The catalog never serializes base URL, connector identity, credential reference, static header,
private template, filesystem path, retry internals, or detailed provider error.

An operator may keep an allowed-destination set private. In that case the catalog does not enumerate
values, but submit accept/reject behavior necessarily remains an authorization oracle; MsgRiver makes
no stronger confidentiality claim.

### A-06.3. ntfy catalog schemas

- `ntfy-topic/1`: closed object `{kind:"ntfy_topic", schema_version:1, topic}` with the product grammar;
- `text/1`: closed object `{kind:"text", schema_version:1, text, title?}` with exact UTF-8 byte limits;
- `ntfy-options/1`: closed object `{kind:"ntfy", schema_version:1, priority?, tags?}` with enumerated
  priority and bounded unique tags; omitted options decode to priority `default`, no tags.

Allowed topic values are included as a schema enum only when `expose_allowed_topics = true`. Otherwise
the grammar is exposed and submission enforces the private allowlist without revealing it.

### A-06.4. Planned generic HTTP/API driver

The driver boundary reserves `generic_http_v1`, but the `0.1.0-alpha` binary rejects that driver value
as `unsupported_driver`; it is absent from every catalog. No dormant request executor ships.

The future implementation is a compiler, not an interpreter at send time. On validated restart it will
compile operator configuration into an immutable `GenericRequestPlan`:

```text
fixed method + canonical endpoint
closed input JSON schemas
typed value -> path-segment/fixed-key-query/JSON-or-form-body destinations
static secret references and auth profile
bounded success/error/retry mapping
bounded optional response JSON-pointer extraction
```

Only `POST`, `PUT`, and `PATCH` are allowed. Path placeholders occupy declared single segments and are
percent-encoded as values; query placeholders can set declared values for fixed keys; body mappings
construct JSON or form data from typed fields; client values never become header names or values,
authentication, template source, JSON pointers, URL structure, or raw bytes. OAuth token endpoints are separate fixed
operator endpoints under the same TLS/redirect/response policies. There is no script, loop,
conditional expression language, remote schema, or runtime template download.

The connector trait and provider catalog are designed so this future driver needs no store/API schema
break: it registers new discriminated destination/content/options codecs and returns the same typed
outcome classes. Promotion requires a separate task, threat model, RED suite, and live proof.

## A-07. Versioned service protocol

### A-07.1. Transport rules

- HTTP/1.1 JSON is used over UDS and optional TCP; HTTP/2 is not needed for the first slice.
- Request path `/v1/...` is the only API-version signal.
- JSON uses UTF-8, duplicate keys are rejected, numbers outside declared integer ranges are rejected,
  and every input object denies unknown fields. One linear lexical preflight that understands strings
  and escapes caps simultaneously open JSON arrays/objects at 64 before typed deserialization; depth 65
  returns the stable malformed-JSON `400` and sends no store command. The pinned serde_json dependency
  retains its recursion limit and MUST NOT enable `unbounded_depth`; the dependency-feature gate checks
  that absence explicitly.
- Duplicate `Authorization`, `Content-Type`, `Content-Length`, or transfer-coding fields, obs-fold,
  conflicting lengths, and `Content-Length` plus `Transfer-Encoding` are rejected before dispatch;
  streaming codecs accept only their one documented framing.
- Maximum request line+headers is 16 KiB, maximum 64 headers, maximum command body 64 KiB, maximum
  non-backup response 256 KiB, body read timeout 5 s, pre-start handler deadline 10 s, and at most 64
  concurrent requests by default. Header acquisition/API-key preclassification has its independent
  16-slot semaphore within that outer cap and releases a slot immediately after classification or the
  five-second timeout; it is a resource bound, not an availability reservation before identity is
  knowable. A mutation that has atomically entered `started` receives a separate
  10 s store-commit/result margin (20 s maximum ordinary handler residence); only documented streaming
  backup/restore transfers use their own longer bounded deadlines.
- Backup artifact download and maintenance restore upload use a separate streaming codec, semaphore,
  byte limit, inactivity timeout, and whole-artifact digest. They never buffer the artifact in memory
  or inherit the ordinary JSON-body exception as an unbounded path. Restore requires canonical declared
  length and encrypted-artifact digest before body streaming; the server verifies both while writing,
  and the fixed control journal binds them to the command before accepting any upload byte.
- `X-Request-Id` is always server-generated. Caller-supplied request IDs are ignored rather than logged.
- TCP requires `Authorization: Bearer`; UDS uses peer mapping or bearer as specified in A-05.
- `Content-Type: application/json` is required for JSON bodies; successful JSON is
  `application/json; charset=utf-8`.
- `Content-Encoding` is absent or exactly `identity`; compressed request bodies are rejected before
  decoding and never gain a larger decompressed budget.

### A-07.2. Complete operation registry

`specs/operations.toml` is immutable input to the RED suite and the normative first-slice registry. One
record fixes operation ID, method, path, binding set, authorization policy ID, request/response codec,
idempotency class, risk class, and exactly one CLI command. Compound method/path rows are invalid.

Idempotency classes are closed and mechanically checked:

| Class | Contract |
|---|---|
| `safe` | Read-only; repetition has no service-state effect. |
| `safe_calculation` | Closed input may be recomputed but creates no authoritative state transition. |
| `domain_key` | The request carries the operation-specific idempotency/replay key; its purpose-separated digest and semantic fingerprint resolve one durable result or conflict. |
| `generation_guarded` | A reversible selected-state request names the exact current resource incarnation/generation pair and complete desired transition; one fixed incarnation-bound last-transition receipt permits only current-result recovery. |
| `idempotent_action` | A monotonic or absorbing addressed SQLite transition whose identity cannot be recreated by an inverse operation makes exact repetition safe; it is not fixed-root or multi-phase. |
| `addressed_state` | The request names an exact fixed-root lifecycle generation/process plus desired monotonic transition; one bounded current/last cell makes repetition safe without caller-key retention. |
| `command_key` | The protected request carries a caller command key; only a purpose-separated keyed digest is retained and same-key/body retry returns one phase/result. |
| `one_time_secret` | A command-key issuance operation whose codec is either single-phase or a closed issue/acknowledge union; plaintext is serialized at most once and retry returns only safe metadata. |

Every `command_key` and `one_time_secret` request uses the operation codec inside a common protected
command envelope. The authenticated stable actor namespace is the principal ID in normal mode,
including the fresh recovery principal, or the fixed state-owner namespace for the UID-0 maintenance
peer. A terminal response carries `command_expires_at`; an effect-bearing continuation carries null and
cannot be removed or reused until it reaches a terminal-safe phase. The terminal half-open window begins
at that phase's durable commit and uses the configured PR-075 duration. Authentication and the
operation's current authorization profile are evaluated before any existing `command_key` or
`one_time_secret` result is returned. The narrowly different effect-free `domain_key` owner-recovery
rule is defined only in A-07.4.

<!-- addressed-state-operation-registry:start -->
The exact 2-operation registry for `addressed_state` is: `clock.acknowledge` and `system.shutdown`.
Their request codecs are direct operation codecs, never the protected command envelope. Each fixes an
exact current address and desired monotonic transition; the response has no `command_expires_at` or
portable reservation. The fixed journal carries one current and one most-recently-completed cell for
each operation. A matching newest-current retry, or completed-result retry before a newer address
exists, returns its safe result; an older/future/different address returns `state_address_conflict`,
and a later lifecycle generation cannot be acted on by an older
request. No other operation may use this class.
<!-- addressed-state-operation-registry:end -->

<!-- generation-guarded-operation-registry:start -->
The exact 5-operation registry for `generation_guarded` is: `admission.set`, `principal.enable`,
`principal.disable`, `grant.put`, and `grant.delete`. `admission.set` uses
`json.admission_set.v1`; `grant.put` uses `json.grant_set.v1`; the two principal actions and grant
deletion use `json.generation_guarded_action.v1`. Every codec requires both
`expected_incarnation` as exactly 64 lowercase hexadecimal characters encoding the authenticated
256-bit selected history epoch and nonzero unsigned `expected_generation`; the first two also carry
their complete desired value, while the operation/path fixes the desired enabled/disabled/present/
absent state for the guarded-action codec. API and CLI send the same fields. No other operation may use
this class, and `idempotent_replace` is not a first-slice class.

Admission owns one fixed nullable receipt, each principal owns one fixed nullable principal-state
receipt, and each principal owns one fixed nullable grant-collection receipt. Each contains prior and
result generation, the exact resource incarnation, stable actor namespace, closed operation/desired-
state/reason fields, and a safe result reference. It has no caller key, secret, general fingerprint,
MAC-key dependency, expiry, or historical chain. Under the store actor and one
`BEGIN IMMEDIATE`, processing after current authentication/authorization is ordered:

1. an exact actor/closed-semantics/`(expected_incarnation, expected_generation)` match against the last
   receipt is recoverable only when its incarnation and result generation are still the complete current
   address, and returns that current safe result without mutation;
2. the complete expected pair equal to the complete current pair plus an already-matching desired value
   returns the current value as an effect-free no-op and need not replace the receipt;
3. every other incarnation or generation mismatch returns `state_generation_conflict` before hold
   disclosure and changes no state, receipt, epoch, or audit row; and
4. only a complete expected-current request with a different desired value enters fresh-mutation hold/
   precedence checks, then atomically applies state, a checked non-wrapping generation increment,
   authorization epoch where applicable, one audit event, and replacement receipt; at `u64::MAX` it
   returns `state_generation_exhausted`, changes nothing, and degrades readiness.

A newer mutation or unrelated mutation of the same principal advances the relevant generation, so an
older receipt cannot be current. For grants, the receipt and generation address the principal's whole
grant collection; a newer change to any provider safely supersedes prior recovery. Same-value ABA,
future/stale generation, old incarnation, changed body, or different actor therefore conflicts even if
current value again resembles the original request. Receipt cardinality is bounded by live principals
plus the singleton admission row, independent of invocation count.

The exact normal guarded-resource writer registry is: admission row — `admission.set` and
`drain.start`; principal resource — `principal.update`, `principal.enable`, and `principal.disable`;
grant collection — `grant.put` and `grant.delete`. A fresh accepted `drain.start` always increments the
admission generation and clears the guarded admission receipt before creating its command/coordinator,
even when admission was already closed; a same-key retry is only command-result recovery. Every fresh
writer at `u64::MAX` returns `state_generation_exhausted` before resource, receipt, authorization epoch,
audit, command, or coordinator mutation. Read/receipt/command recovery and an exact same-value guarded
no-op remain available.

The resource incarnation is exactly the selected authenticated structured 256-bit history epoch.
Bootstrap creates the initial incarnation; the exact branch-replacement registry is `restore.create`
and `upgrade.rollback`, each of which allocates a new epoch/incarnation, resets every surviving guarded
resource generation to one, and clears receipts after its typed selected state is complete. Ordinary
restart and the continuation registry `configuration.activate`, `state_key.rotate`, `state_key.retire`,
`upgrade.migrate`, `upgrade.activate`, and forward repair preserve the complete address and allocate no
serial. A-10.2's fixed-root allocator is the sole source of branch incarnations. Separate prepare,
backup, restore, clock, storage, and shutdown admission holds never overwrite the operator admission
row. No unlisted writer or branch transition may change, preserve, reset, or allocate a guarded address
by inference.
<!-- generation-guarded-operation-registry:end -->

Every fixed-root journaled mutator is `addressed_state`, `command_key`, or `one_time_secret`; it may not use
`idempotent_action`. The catalog's `fixed_root_journaled_operations` registry freezes that set and the
spec lint checks it against an independent expected set. It contains every maintenance-bound mutator
in these three classes plus normal-UDS-only `upgrade.prepare` and `upgrade.activate`: prepare durably
binds A-10.7's complete exit capacity before its selected coordinator, while activate writes or resolves
divergence provenance and its command result in the same cross-store protocol. The `recovery_key.generate` codec is explicitly
tagged `generate` or `acknowledge`, with the same command key and exact confirmation digest in the latter
phase. An acknowledgement whose tuple has no matching generated intent returns `command_conflict`
before journal or ring mutation and creates no command reservation; it is not a fresh issuance path.
API-key issue/rotation are the single-phase variant and never accept an acknowledgement tag.
The optional catalog field `one_time_mode` is required exactly for those three operations and is frozen
independently as `single_phase` or `escrow_acknowledgement`; adding the class without selecting and
implementing one of those modes fails the spec lint.

Build code parses the checked-in catalog into generated strongly typed descriptors, but the expected
set never originates from implementation enums. Separate compile/test assertions prove:

1. every catalog ID has one server handler and authorization policy;
2. every server route maps to exactly one catalog method/path/binding record;
3. every catalog ID has one `msgriver-client` request implementation and one Clap command path;
4. no non-presentation CLI command exists without a catalog ID;
5. generated docs and stable error matrices cover the same exact set; and
6. route, client, and CLI dispatch are exhaustive over a generated `OperationId`.

`serve` and `maintenance serve` are the sole service-lifecycle exceptions. `help`, `version`, shell
completion, renderer selection, and selecting a client-side upload/download file do not inspect or
mutate service state and are presentation, not hidden operations. Health, readiness, and metrics use
only their versioned catalog paths; systemd and deployment tooling invoke those operations over the
appropriate authenticated binding, with no unversioned HTTP aliases or second handlers. One-time
secrets exist only in their operation response and receive the same protected stdout treatment through
CLI rendering.

Authorization profile IDs in the catalog have one closed meaning:

| Profile | Effective rule after A-05 authentication |
|---|---|
| `authenticated_catalog` | `submit` or `status:own`; results are independently provider-grant filtered |
| `submit` | exact authenticated enabled owner for an existing A-07.4 domain-key hit; otherwise effective `submit` plus current provider grant for a fresh command |
| `status_own_or_operator` | effective `operator`, or `status:own` plus owner match; mismatch is uniform 404 |
| `cancel_own_or_operator` | effective `operator`, or `cancel:own` plus owner match; mismatch is uniform 404 |
| `operator` | effective `operator` on any binding allowed by the operation record |
| `local_operator` | normal UDS and effective `operator`, including operator in the peer ceiling |
| `local_operator_or_state_owner_peer` | `local_operator` in normal mode; authenticated state-owner peer in maintenance mode |
| `state_owner_peer` | maintenance UDS peer UID exactly 0 through the root-owned mode-`0600` socket in v1 |
| `local_recovery_operator` | normal UDS fresh restore-specific recovery principal/mapping, never restored authority |
| `probe_by_binding` | normal UDS requires an enabled peer mapping and any nonempty effective scope under A-05 (a presented bearer still cannot fall back); maintenance UDS requires UID 0; TCP requires a valid bearer and any nonempty principal/key scope intersection |

An unknown profile is a build error. Binding checks happen before handler dispatch, and a route absent
from that binding is 404/405 according to frozen protocol tests rather than a callable denied path.
Router generation orders exact literal segments before parameters and rejects ambiguous equal-specificity
patterns. In particular, `GET /v1/admin/restores/current` can never dispatch to
`GET /v1/admin/restores/{restore_id}`; generated route tests exercise both declaration orders.

### A-07.3. Provider catalog response

```json
{
  "catalog_generation": "sha256-base64url",
  "providers": [],
  "schemas": {}
}
```

`If-None-Match` yields `304` only after authentication/authorization and generation computation.
Provider detail returns uniform `404 resource_not_found` for absent, disabled, or unauthorized IDs.
Catalog responses are capped; an operator cannot enable a configuration whose safe catalog exceeds
the cap.

### A-07.4. Submit request and response

```json
{
  "idempotency_key": "backup:2026-07-30:ntfy",
  "provider": "ops-ntfy",
  "destination": {
    "kind": "ntfy_topic",
    "schema_version": 1,
    "topic": "obliance"
  },
  "content": {
    "kind": "text",
    "schema_version": 1,
    "title": "Backup",
    "text": "Backup completed"
  },
  "options": {
    "kind": "ntfy",
    "schema_version": 1,
    "priority": "default",
    "tags": ["heavy_check_mark"]
  },
  "expires_at": "2026-07-30T14:00:00.000Z",
  "correlation_id": "backup:2026-07-30"
}
```

Dates are RFC 3339 UTC with exactly millisecond precision and `Z`; offsets, leap seconds, excessive
precision, and non-canonical equivalents are rejected. `options`, `expires_at`, and `correlation_id`
may be absent; `null` is rejected where absence is the contract.

Fresh `201` and deduplicated `200` share one response shape:

```json
{
  "message_id": "019...",
  "state": "queued",
  "deduplicated": false,
  "idempotency_expires_at": "2026-08-06T13:00:00.000Z",
  "effect_may_have_occurred": false,
  "duplicate_effect_possible": false,
  "created_at": "2026-07-30T13:00:00.000Z"
}
```

After authentication and bounded strict decoding, the server canonicalizes with the request's supported
schema/canonicalization version and performs the reserved idempotency pre-pass before checking current
provider availability, grant, connector generation, admission state, or fresh quota. An unexpired hit
means its half-open boundary is still above A-11.5's effective durable authenticated safe-time high-
water. A row whose boundary is at or below that high-water is proven-expired and can never become a hit
again, including during a later clock hold. If the current accepted clock observation would cross a
boundary above the durable high-water, the pre-pass first advances that high-water through an A-11.5
durable checkpoint/mirror; failure returns durability unavailable without old-result disclosure or
fresh admission. An unexpired hit compares the stored fingerprint and returns existing/conflict only
when the request is currently authenticated as the exact enabled stable owner principal. That result-recovery path intentionally does
not require current submit scope or provider grant even if either no longer permits a fresh command;
it creates no effect and is not a command-key authorization bypass. A revoked/expired credential,
disabled principal, or different principal fails before existence/result disclosure. A miss enters
admission, where current scope/provider/grant/config validation occurs and the same
lookup is atomically repeated before quota and insert. A fresh command is accepted only if the provider
remains enabled and the exact connector identity generation used for validation can be pinned in that
same transaction.

### A-07.5. Safe status and attempt evidence

Status includes:

```text
message_id, provider_id, state, hold_reason?, created_at, updated_at, expires_at?, terminal_at?,
attempt_count, next_attempt_at?, cancel_requested, effect_may_have_occurred, duplicate_effect_possible,
outcome_class?, payload_available, idempotency_expires_at?, replay_of?, replay_children_count
```

It never includes destination/content, raw idempotency/correlation values, fingerprint, provider body,
credential generation, endpoint, or fence. An operator-only internal diagnostic may include connector
identity/config generation IDs and safe error codes but not secret/private configuration.

Attempt evidence includes attempt ID/ordinal, safe start/finish times, state (`in_flight`, `completed`,
`orphaned`), safe outcome class, ambiguity flag, and provider acknowledgement ID only if the driver's
threat model classifies that ID as non-sensitive. It excludes HTTP body/headers and destination.

### A-07.6. Error envelope

```json
{
  "error": {
    "code": "idempotency_conflict",
    "message": "The idempotency key already identifies a different command.",
    "request_id": "019...",
    "retry_after_ms": null
  }
}
```

Stable code families and HTTP mappings:

| HTTP | Codes |
|---:|---|
| 400 | malformed JSON, duplicate field, invalid content type |
| 401 | missing/invalid/revoked/expired credential |
| 403 | authenticated principal lacks operation scope on a non-resource-global action |
| 404 | unknown or unauthorized resource/provider |
| 405 | method is absent for this registered path/binding |
| 406 | requested response representation is unsupported |
| 408 | request/body inactivity, or mutation deadline after successful atomic queued cancellation |
| 409 | idempotency/command conflict, `command_namespace_changed`, `state_address_conflict`, `state_generation_conflict`, `shutdown_in_progress`, `drain_in_progress`, `maintenance_transition_busy`, `upgrade_prepare_in_progress`, `upgrade_activation_pending`, `recovery_key_pending_escrow`, `mac_key_ring_full`, `mac_key_identity_conflict`, invalid state transition, active state owner |
| 413 | body/header/response contract too large |
| 415 | unsupported media type or non-identity content encoding |
| 422 | closed-schema/semantic/config validation failure |
| 429 | pre-auth/principal/provider/admission limit, with bounded jittered hint |
| 503 | store/control reserve/durability/restore hold unavailable, `control_capacity`, `state_generation_exhausted`, `state_incarnation_unavailable`, `mac_key_serial_exhausted`, `canonicalizer_unavailable`, `idempotency_evidence_corrupt`, exact `clock_hold`, or `operation_outcome_unknown` after mutation start |

Messages are constant templates selected by code; they never interpolate caller/provider input.
`command_conflict` means a retained actor/operation/key record has an incompatible semantic or phase
fingerprint. `command_namespace_changed` means that tuple belongs to a different restored runtime and
remains reserved until its reported terminal `command_expires_at`. Neither code reveals the stored
fingerprint, raw command key, actor display data, or prior result.
`state_address_conflict` means an addressed-state request does not name the current or last completed
hold/process address; it reveals no older result and requires a fresh status read. `shutdown_in_progress`
means the same current process already has a different accepted monotonic shutdown transition.
`state_generation_conflict` means a generation-guarded request neither names the complete current
resource-incarnation/generation pair nor matches the still-current incarnation-bound last receipt for
the same actor and semantic request. It returns no historical result, performs no mutation, and directs
the authorized caller to read current state; the safe current pair may be included only where the
corresponding show/list response already discloses it to that authorization profile.
`state_generation_exhausted` means a guarded resource reached `u64::MAX`; it has no retry hint, never
wraps or mutates, and keeps readiness degraded until a supported fresh branch incarnation or future
migration widens the generation representation.
`state_incarnation_unavailable` means a branch-creating transition cannot allocate its next structured
incarnation because the fixed-root branch serial is exhausted or its authenticated allocator state or
derived target is inconsistent. It has no retry hint and is returned before staging, selected-state,
pointer, or allocator mutation beyond an already durable same-intent serial burn. Exact same-command
recovery is resolved first; for a genuinely fresh branch transition, an existing restore/upgrade hold
that forbids the operation wins before allocator evaluation, while a transition permitted through its
own hold reaches allocator validation before clock evaluation. Thus serial exhaustion cannot disclose
an otherwise-hidden hold and cannot be bypassed by combining it with `clock_hold`.
`operation_outcome_unknown` is emitted only after the actor lifecycle token reached `started` and the
bounded result could not be delivered; it explicitly says that commit may have occurred and requires
same-key/idempotent recovery. It is never interchangeable with `408`, whose queued-cancellation CAS is
proof that no mutation began.
`clock_hold` always carries a null `retry_after_ms`; operator acknowledgement or a validated settle
window has no truthful bounded retry duration. `upgrade_activation_pending` identifies a selected-state
mutation forbidden by A-10.7's rollback-eligible read-only phase and takes precedence if the same
mutation is also clock-held. `upgrade_prepare_in_progress` identifies `admission.set` serialized after
prepare's initial quiescing commit but before either terminal prepare transaction; it has no bounded
retry hint, reveals no coordinator detail, and takes the same precedence over `clock_hold` as
`upgrade_activation_pending`. `control_capacity` is emitted only before a fixed-root intent/effect when
its worst-case projected checkpoint cannot fit the ordinary budget; reserved reconciliation and
capacity-reducing operations do not return it merely because ordinary admission is full.
`recovery_key_pending_escrow` means the sole bounded successor slot is occupied; it reveals no secret,
digest, generation identifier, or prior command result.
`mac_key_ring_full` (409) has two first-slice emitters: rotation when a purpose's retained ring has
reached `MAX_RETAINED_MAC_KEYS_PER_PURPOSE`, and restore merge when a complete staged-key union would
exceed that same per-purpose bound. Rotation MUST evaluate selected-origin/high-water integrity, then
serial exhaustion, then retained-ring capacity, and MUST return this code before any entropy draw, key
file, journal intent, high-water, or ring mutation (R3-INV-106). Restore merge MUST apply identity
consistency and byte-identical deduplication before capacity, and MUST return this code before destination
key-file staging, generation finalization, pointer selection, or any selected-state mutation. Candidate
restore key rows become available only after artifact authentication and decryption, so the durable
command/input intent and any applicable same-intent branch-serial burn already exist before either
restore-merge `409`. Rotation recovery retires a dependency-free generation or waits for its covering
window; restore recovery waits for the covering artifact/new-host reservation dependencies or uses an
eligible artifact whose staged union fits. Both emitters fail closed and expose no caller-visible key
identity. `mac_key_identity_conflict` (409) means two ring entries carry an equal `MacKeyRef` but unequal
key bytes, which is corruption. Restore merge MUST return it after authenticating and decrypting the
candidate rows but before destination key-file staging, generation finalization, pointer selection, or any
selected-state mutation; its durable command/input intent and any applicable same-intent branch-serial burn already
exist. Equal `MacKeyId` values under different purposes remain valid and resolve to distinct paths
(R3-INV-108). `mac_key_serial_exhausted` (503) is returned when one `(origin, purpose)` has
reached `u64::MAX`; it is returned before any effect and degrades readiness with reason
`mac_key_serial_exhausted`. Unlike `incarnation_exhausted` it is not terminal for the owner root: it is
recoverable without data loss by any supported branch transition, which allocates a fresh origin whose
serial restarts at 1 (R3-INV-107). `canonicalizer_unavailable` (503) and `idempotency_evidence_corrupt`
(503) are the AP3-002 dispatch outcomes D-5 and D-6/D-7: the former means the row's canonicalization
version or a row-referenced schema codec is unavailable and the service never falls back to the active
version; the latter means a corrupt evidence row. Both fail closed, carry no caller-visible detail beyond
the code, and never dedupe, conflict, or create.

### A-07.7. Pagination cursor

List order is `(created_sequence ASC, message_id ASC)`. The bounded opaque cursor encodes only version,
last sequence/ID, and expiry. Every page independently authenticates, authorizes, and takes filters from
the current request; the cursor can only choose a validated restart point inside that already scoped
query and cannot widen filters or principal visibility. Tampering may skip/duplicate the caller's own
page progression, not access another scope. Page size defaults 50, maximum 200. Inserts after the last
key appear on later pages; deletions do not duplicate prior rows. Cursor expiry returns a stable
restart-list error rather than guessing. No cursor MAC/key lifecycle exists.

The immutable restore-safety report uses the same bounded page size but a distinct
`query.restore_report_page.v1` cursor. It carries report digest, tagged section, last generated ID, and
expiry; the server accepts it only against the one currently held report with that exact digest and
re-authorizes every page. The cursor cannot select another report or alter summary/counts. Every page
repeats the immutable digest, total count per section, and page ordinal, and remains below the 256-KiB
response ceiling. This is digest binding, not an authentication capability or a second cursor-key
lifecycle.

## A-08. CLI and operator experience

### A-08.1. Connection profile

The CLI reads non-secret connection settings from a user config file or explicit non-sensitive
`--socket`/`--server` option. API secrets come only from a protected file descriptor/file reference
named by the profile; environment secret values are rejected in v1 and the secret value
itself is never an argument. UDS is the default.

### A-08.2. Sensitive request input

`msgriver send --request @-` reads one complete JSON command from stdin. `--request @/protected/path`
opens a regular file without following a final symlink, checks ownership/mode on Unix, bounds it before
allocation, and reads once. The same envelope rule applies to replay, secret import/issue, destructive
acknowledgements, configuration activation, and every other request containing caller-sensitive or
secret-bearing values; the client moves validated values into path/query/body only after parsing. There
are no `--text`, `--topic`, `--idempotency-key`, `--correlation-id`, `--api-key`, `--recovery-key`, or
inline-config value flags. Generated non-secret resource IDs (`message_id`, attempt, principal,
provider, key, backup, restore, upgrade, and generation IDs) may be positional/flag values and are never
authorization capabilities. The five generation-guarded commands additionally require
`--if-incarnation <64-lowercase-hex>` and `--if-generation <u64>` (or the identical
`expected_incarnation` and `expected_generation` fields in protected request JSON); the CLI never
performs a hidden read-then-write or silently retries with either newer address component. Only non-
sensitive connection/output controls and explicit confirmation switches may otherwise be ordinary flags. A future interactive builder may use the provider catalog,
but it must submit the same closed request and keep sensitive input off argv/history.

### A-08.3. Output and exit codes

- Human output leads with message/state and uncertainty; a dedupe result says `Existing command`, not
  `Accepted`.
- `--json` emits the protocol object unchanged except transport metadata.
- Default list output excludes payload, destination, IDs classified sensitive, and private config.
- API keys print once to stdout only; every other message goes to stderr so redirection is safe.
- A generated recovery key auto-acknowledges escrow only with an explicit protected output path. The
  CLI creates the absent regular file with no-follow/`O_EXCL`, mode `0600`, writes and `fsync`s it,
  `fsync`s its parent directory, reopens without following links, and verifies owner/mode/length and the
  confirmation digest before sending the `acknowledge` variant of the same operation with the same
  command key and exact digest. The initial call is the closed `generate` variant. Stdout, pipe, or
  caller-owned descriptor output leaves the server key `pending_escrow`; the operator must durably
  escrow it and explicitly send that `acknowledge` variant in the original protected command envelope.
- Externally duplicating replay requires a replay-request key inside protected request input plus
  `--confirm-replay` for non-interactive execution.
- Restore resume's protected request contains report digest, watermark, and the six A-14.4
  acknowledgement fields. The CLI additionally requires
  `--acknowledge-rpo <watermark>`, `--confirm-possible-duplicates`,
  `--confirm-resurrected-payload`, `--confirm-unresolved-tombstones`,
  `--confirm-credential-quarantine`, and
  `--tcp-policy <remain-disabled|enable-after-replacement-authorization>`. Each switch must match the
  request and held report; switches never synthesize, omit, or override an API field.

Exit classes are stable: `0` success/deduplicated success, `2` local usage/config, `3` validation,
`4` authentication/authorization/not-found, `5` conflict/state, `6` retryable overload/unavailable,
and `70` unexpected internal failure. There is no unregistered client-side wait capability or phantom
provider-terminal exit class in the first slice. Secret-bearing error context is redacted before mapping.

### A-08.4. CLI is an API client

After parsing protected local input, every non-lifecycle CLI command builds the same typed wire request
used by an application client and invokes the descriptor in A-07.2. It does not link
`msgriver-store`, receive a SQLite path, inspect service files, or call a privileged in-process handler.
Human and JSON renderers consume the API response/error envelope only.

Normal administration selects the primary UDS and refuses TCP for local-only operations. Bootstrap
and restore select the maintenance UDS and fail if its peer/mode/owner checks do not match the local
profile. Backup download and restore upload stream between an already-open protected file descriptor
and the API; filesystem paths remain CLI-side and never become server-side request parameters.

The parity test starts real normal and maintenance listeners around isolated state, derives expected
cases from the separately frozen TOML catalog, and exercises each `OperationId` directly and through
the executable. It
compares authorization decision, normalized response/error code, durable state delta, audit event, and
captured redaction surfaces. The test also inspects crate dependencies and syscall-open traces to prove
the CLI does not open the database, state generation, operational configuration, or service key rings.

## A-09. Message and attempt state machine

### A-09.1. State representation

The durable message state is one closed enum plus orthogonal fields; ambiguity is never encoded only in
a transient state name:

```text
state: queued | held | delivering | retry_scheduled |
       provider_accepted | failed | cancelled | expired
hold_reason: connector_unconfigured | clock_anomaly | upgrade_quiescing |
             storage_safety | restore_hold | retry_jitter_unavailable | null
cancel_requested: bool
effect_may_have_occurred: bool
duplicate_effect_possible: bool
known_provider_ack_attempt_id: optional AttemptId
deferred_outcome_class: optional transient | rate_limited | auth_or_config | ambiguous
deferred_relative_delay: optional bounded duration
deferred_validated_retry_after: optional ValidatedRetryAfter
```

The deferred-projection hold set is exactly `clock_anomaly`, `upgrade_quiescing`, and
`retry_jitter_unavailable`; it is never an ordinary hold, and the generic ordinary hold-clear transition
MUST exclude it. Clock anomaly and upgrade quiescence are stricter authority holds and win the initial
label when a retryable outcome also has an unavailable jitter source. The deferred fields are non-null
only while one of that closed set has postponed ordinary outcome projection. Jitter-unavailable rows
retain class and validated retry-after evidence but have null multiplier and derived relative delay. A
clock/upgrade projection invokes jitter only through the persisted reference; if unavailable, it moves to
`retry_jitter_unavailable` with every deadline still null. Every deferred field is cleared in the same
transaction that materializes its message and shared-circuit deadlines or terminal result; no scheduler
index treats a null deferred deadline as eligible work.

“Terminal” means no scheduler-created attempt remains eligible. A late, verifiable provider
acknowledgement may correct `failed`/`cancelled`/`expired` to `provider_accepted`; this is evidence
correction, not a new attempt or reopening. No weaker late result may change a terminal state.

Terminal precedence is deterministic: known provider acknowledgement wins; otherwise an explicit
cancel command evaluated in the same actor transaction wins over newly eligible expiry; expiry wins
over retry/max-attempt exhaustion. Once any terminal commit exists, later cancel, expiry, failed guard,
ambiguity, or other non-acceptance is an idempotent no-op returning that state. Matching verifiable
acceptance is the sole exception and sole terminal-to-terminal transition named above. Actor
serialization and transaction sequence make the winner reproducible.

### A-09.2. Transition table

| Current | Event/guard | Next | Required evidence |
|---|---|---|---|
| none | accepted transaction | `queued` | initial status/idempotency/connector snapshot atomic |
| `queued`/`retry_scheduled` | connector cannot operate | `held` | safe hold reason; no attempt |
| `held` (ordinary reason) | ordinary hold clears and not expired/cancelled | `queued` | excludes every deferred-projection hold; hold-cleared audit |
| `queued`/`retry_scheduled` | fair claim | `delivering` | lease/fence + prepared attempt with active purpose-09 `MacKeyRef` committed |
| `delivering` prepared | dispatch mark commits | `delivering` dispatching | possible-effect marker begins conservatively |
| `delivering` prepared | lease expires/crash recovery | `queued`, `held`, `cancelled`, or `expired` | no effect uncertainty; current guards decide |
| `delivering` dispatching | lease expires/crash recovery | retry/cancel/expiry/exhaustion result | ambiguity true; retry implies duplicate possible |
| `delivering` | acknowledged under current fence | `provider_accepted` | provider ack attempt, effect=true |
| `delivering` | permanent under current fence | `failed`, `cancelled`, or `expired` | safe error; acceptance/cancel/expiry total order already applied |
| `delivering` | retryable non-acceptance and unavailable `JitterSource` under current fence with no clock/upgrade hold | `held` (`retry_jitter_unavailable`) or precedence terminal | persist outcome, selected ref, class, validated retry-after; null multiplier/delay/lease/deadlines; no effect |
| `held` (`retry_jitter_unavailable`) | observed purpose-09 repair/activation or bounded sweep, with validated safe time and no effective clock, upgrade, restore, or storage hold | ordinary outcome projection or unchanged | reapply terminal precedence; derive only with persisted ref; unavailable has no self-wake; an absent safe-time proof or any listed hold leaves the row, its null deadlines, and its label unchanged |
| `held` (`retry_jitter_unavailable`) | clock anomaly becomes effective | `held` (`clock_anomaly`) | clock is stricter; retain deferred evidence and persisted ref, and leave every deadline null |
| `delivering` | transient/rate-limited/auth-or-config/ambiguous under current fence while clock-held | `held` (`clock_anomaly`) or precedence terminal | clock wins over jitter unavailability; attempt truth/sticky uncertainty; persisted ref; null multiplier/delay/deadlines when source unavailable |
| `delivering` | transient/rate-limited/auth-or-config/ambiguous under current fence while upgrade-quiescing | `held` (`upgrade_quiescing`) or precedence terminal | upgrade wins over jitter unavailability; retained outcome/relative evidence and null deadlines; otherwise terminalize under total order |
| `held` (`upgrade_quiescing`) | failed prepare or selected upgrade hold-clear with safe clock | ordinary outcome projection or `retry_jitter_unavailable` | derive through persisted ref before projection; one conservative message deadline plus any shared circuit deadline, or terminal precedence; hold-cleared audit |
| `held` (`upgrade_quiescing`) | clock anomaly prevents projection | `held` (`clock_anomaly`) | deferred outcome/relative evidence retained; every deadline remains null |
| `held` (`upgrade_quiescing`) | later cancel or expiry/max-age/attempt crossing | unchanged plus retained guard | only the ordinary-outcome projection may release; generic maintenance excludes row |
| `delivering` | transient/rate-limited | `retry_scheduled` or cancel/expiry/exhaustion terminal | next deadline or terminal reason |
| `delivering` | auth-or-config | `retry_scheduled` or cancel/expiry/exhaustion terminal | bounded message deadline plus one shared open-circuit probe deadline |
| `delivering` | ambiguous | retry/cancel/expiry/exhaustion result | effect=true; duplicate=true if another attempt can occur |
| non-terminal except `delivering` and `held` (`upgrade_quiescing`) | cancel | `cancelled` | no new attempt can begin |
| `delivering` | cancel | unchanged + `cancel_requested` | eventual result follows product precedence |
| `queued`/ordinary `held`/`retry_scheduled`/`held` (`retry_jitter_unavailable`) | expiry | `expired` | excludes clock/upgrade deferred holds; no new attempt begins at equality boundary |
| any | late stale non-ack | unchanged | append orphan evidence only |
| any non-accepted nonterminal state or `failed`/`cancelled`/`expired`, with matching attempt evidence | late verifiable ack | `provider_accepted` | acceptance wins; sole terminal promotion; retain prior state/ambiguity history; no new attempt |

### A-09.3. Prepare-before-dispatch protocol

One external attempt uses three durable phases:

1. **claim/prepare:** transaction changes the eligible message to `delivering`, increments attempt
   ordinal and lease generation, selects exactly one active `RetryJitterV1` `MacKeyRef`, stores that
   public reference with random fence token/lease expiry, and inserts attempt `prepared`; absent or
   corrupt active purpose-09 state adds the closed `retry_jitter_unavailable` readiness reason and fails
   this transaction before network I/O;
2. **dispatch mark:** immediately before any network byte, a second fenced transaction rechecks current
   lease/fence, cancellation, expiry/max age, connector/config/credential hold, restore/upgrade/clock/
   storage/effect hold, and provider circuit; it renews the lease through at least connector total
   timeout plus result-commit margin, changes the attempt to `dispatching`, and conservatively sets
   `effect_may_have_occurred = true`;
3. **outcome:** connector call returns a typed outcome; fenced transaction records it and transitions.

A failed dispatch recheck returns work to the exact eligible/held/cancelled/expired state without
network I/O. A crash in `prepared` is recoverable without external-effect uncertainty. A crash in
`dispatching` is recovered as ambiguous and any retry sets duplicate possibility. A crash before or
after committing an unavailable-source hold leaves either the fenced outcome transaction or its
predecessor wholly visible; a crash during its recovery repeats only the fenced, persisted-reference
projection and can publish it at most once. This narrow extra transaction is the price of distinguishing
“worker owned it” from “provider effect may have started.”

### A-09.4. Fence arbitration

Every outcome update has `WHERE message_id=? AND lease_generation=? AND fence_token=? AND
state='delivering'`. Zero changed rows means stale evidence:

- a stale transient/permanent result appends `orphaned` attempt evidence and changes nothing else;
- stale ambiguity ORs sticky uncertainty/duplicate flags without replacing current scheduling;
- a cryptographically/structurally valid provider acknowledgement records the ack and may promote the
  message to `provider_accepted`; if another attempt existed, duplicate possibility remains true;
- no path decrements attempt count, clears sticky flags, deletes newer evidence, or reuses a fence.

Lease TTL defaults to 30 seconds, connector total timeout to 5 seconds, and commit margin to 5 seconds;
configuration requires `lease_ttl > timeout + margin` and a minimum 5-second margin; exact equality is
invalid. Lease recovery
uses persisted UTC expiry plus clock-guard rules; in-process wakeups use monotonic time.

## A-10. SQLite state and transaction contracts

### A-10.1. Database profile

The bundled SQLite version must be 3.51.3 or newer. Before readiness, startup compares the linked
runtime SQLite version number with that minimum, records the exact version in startup evidence and
metrics, and fails closed below the floor. It then opens a single read/write connection on the store
actor and verifies, rather than merely sets, this profile:

```text
journal_mode = WAL
synchronous = FULL
foreign_keys = ON
trusted_schema = OFF
recursive_triggers = OFF
busy_timeout = 5000 ms
wal_autocheckpoint = bounded configured page count
journal_size_limit = bounded configured bytes
```

The database must be on a local filesystem. A failed pragma, unsupported WAL transition, failed
integrity check, schema checksum mismatch, or `synchronous != FULL` prevents readiness. There is no
runtime option to lower durability. The store actor is the only writer/checkpointer; backup uses one
incremental backup handle created from that exact actor-owned source connection and never checkpoints
concurrently. A bounded 2–4 connection read-only WAL pool serves ordinary snapshot reads; it sets
`query_only=ON`, has short read deadlines, and cannot acquire write transactions.

While that retained backup handle shares the source `Connection`, actor mutations use pinned
`rusqlite 0.40.1`'s safe
`Transaction::new_unchecked(&source, TransactionBehavior::Immediate)` (or the equivalent checked
wrapper owned by the store module), which takes `&Connection`; "unchecked" delegates nesting
prevention to the store owner and SQLite rather than requiring Rust `unsafe`. Every normal transaction
path explicitly consumes `commit()`, `rollback()`, or `finish()` and handles the returned result.
Rollback-on-drop RAII is only a backstop because its error cannot be observed. The ordinary
`Connection::transaction*` and savepoint helpers require `&mut self` and are forbidden on this path;
raw `BEGIN`/`COMMIT`/`ROLLBACK`, a second writer, and scoping/recreating the backup handle per step are
also forbidden. Store ownership prevents nesting. Any explicit rollback/finish failure poisons the
actor connection, rejects further commands and backup steps, drops the retained backup handle and
connection, and degrades readiness. Progress resumes only after a fresh connection passes the complete
startup profile and durable-prefix reconciliation within the original job deadline.

SQLite owns DB/WAL synchronization under the verified profile. Bootstrap creates the generation and
database with no-follow/exclusive semantics, completes schema/checkpoint/close, fsyncs the database and
every newly created state-key file, then fsyncs the generation and parent directory before the active
pointer can name it. Canonical operational configuration is a SQLite row, not a parallel file. WAL/SHM
and lock directory entries are included in structural/fault evidence; the application never
substitutes a main-file fsync for SQLite's WAL barrier. Bootstrap and stopped-state clone production write
the pointer mirror before final checkpoint/close. Their sealing postcondition incorporates committed source
WAL content and prevents WAL/SHM from changing the ensuing descriptor-bound read-only view. [PENDENTE: Task0146/0147] The former descriptor-bound sealing/checkpoint/FFI-VFS requirements remain future conditions only; no current implementation or comparison may claim them.


### A-10.2. Logical schema

| Table | Key fields and purpose |
|---|---|
| `schema_migrations` | version, checksum, applied binary/time |
| `meta` | schema/config version, runtime instance and immutable lineage IDs, transaction/auth epochs, admission tuple plus 32-byte incarnation/two-limb guarded generation and fixed incarnation-bound receipt, effect/restore/upgrade holds, reports, active 256-bit history epoch/resource incarnation plus restore-comparison anchor/head sequence+digest, selected `OriginIncarnation` plus one authenticated two-limb `mac_serial_high_water` pair for every closed `MacPurpose`, immutable nonzero 32-byte active-state-pointer certificate digest, last safe wall time |
| `principals` | stable ID, display name, enabled, scopes, quota profile, 32-byte incarnation + two-limb non-wrapping resource generation + fixed incarnation-bound guarded-principal receipt, 32-byte incarnation + two-limb grant-collection generation + fixed incarnation-bound guarded-grant receipt |
| `principal_provider_grants` | principal/provider allowlist with unique pair |
| `peer_mappings` | generated mapping ID, exact UID, principal, scope ceiling, enabled/status/generation |
| `api_keys` | public key ID, principal, `ApiKeyVerifyV1` `MacKeyRef` columns plus keyed verifier, scopes/status/timestamps; no secret |
| `configuration_generations` | canonical complete non-secret config bytes/digest/status/compatibility evidence |
| `connector_identities` | immutable non-secret driver/endpoint/policy snapshot and config generation |
| `providers` | public provider ID, current connector identity, enabled/catalog-safe fields |
| `messages` | owner, provider/snapshot, schemas, nullable payload blobs, state/hold, times, sticky flags, lease, replay lineage, byte charge |
| `idempotency_records` | principal + `LookupV1`/`FingerprintV1` `MacKeyRef` columns plus keyed lookup digest and fingerprint tag, `canonicalizer_version`, and the three persisted per-role schema tuples `(schema_id, kind, schema_version)` for destination, content, and options (options nullable only with no options segment), message, expiry |
| `operation_commands` | operation + stable actor namespace + `CommandLookupV1`/`CommandSemanticFingerprintV1`/`CommandPhaseFingerprintV1` `MacKeyRef` columns plus keyed command digest, optional backup-portable fixed-root reservation digest/`PortableReservationV1` `MacKeyRef`, separately keyed semantic/phase fingerprints, source runtime/process, phase, safe result references, terminal time and exact nullable expiry; no raw key/secret |
| `attempts` | message/ordinal, fence generation/tag digest, `RetryJitterV1` `MacKeyRef` plus persisted jitter `multiplier_milli` and relative delay, phase/times, config generations, safe outcome/ack |
| `replay_requests` | actor + `ReplayLookupV1`/`ReplayFingerprintV1` `MacKeyRef` columns plus keyed replay digest, source and single child message |
| `provider_runtime` | circuit state, not-before, probe lease, failure class, scheduler cursor |
| `scheduler_principal_cursor` | provider + last principal for deterministic two-level fairness |
| `purge_tombstones` | message, durable purge instant, closed source/reason, producing history epoch + comparison batch/ordinal |
| `history_epochs` | immutable structured 256-bit epoch ID/resource incarnation (192-bit fixed-root namespace + 64-bit branch serial), typed bootstrap/restore/rollback origin transition, exact parent epoch/head sequence+digest when present, activation-certificate digest |
| `restore_comparison_batches` | history epoch, contiguous batch sequence, source transaction sequence, exact event count, prior digest, canonical batch digest; typed epoch-boundary parent fields only on the first batch of a new epoch |
| `restore_comparison_events` | batch sequence + contiguous ordinal, generated command/message/attempt references, closed lifecycle event, terminal/effect/ambiguity flags, and complete non-sensitive purge-tombstone projection; no payload, destination, principal display data, or provider response |
| `audit_events` | generated IDs, actor/message/provider references, event code/time; no arbitrary values |
| `backup_jobs` | job state plus internal publication phase, generated temp/final basenames, expected artifact digest/size, cancellation, comparison-pin ownership, terminal reason, immutable validated-safe-UTC execution deadline with checked component maxima/margins and same-boot monotonic mirror metadata, and the distinct retention deadline; no caller path |
| `backup_history` | job, artifact digest, source instance/lineage, snapshot watermark/result, base purge-tombstone count/digest/watermark, history epoch + comparison batch head sequence/digest and exact nonempty-restore support deadline; no payload/path in logs |
| `upgrade_state` | upgrade/transition IDs, `quiescing`/prepared phase, immutable safe-UTC prepare deadline plus component maxima/margins and same-boot monotonic mirror metadata, prepared source and exact store/effect/comparison plus checkpoint/tail heads and lifecycle transcript commitment, source/target generation/schema, target certificate digest, rollback eligibility, divergence digest, and activation/repair status |

#### A-10.2.1. Migration-ledger foundation

The first independently invocable catalog entry is version `1`. Its embedded
SQL creates only `schema_migrations` with the following closed SQLite schema:
`version INTEGER PRIMARY KEY CHECK (version > 0)`, `checksum BLOB NOT NULL
CHECK (length(checksum) = 32)`, `applied_binary BLOB NOT NULL CHECK
(length(applied_binary) > 0)`, and `applied_at_unix_ms INTEGER NOT NULL`.
The catalog checksum is SHA-256 over the exact embedded SQL bytes and is stored
as its 32 raw digest bytes, not formatted text.

The primitive receives `MigrationProvenance` explicitly from its maintenance
caller: nonempty opaque `binary_identity` bytes and an `i64`
`applied_at_unix_ms`. It neither reads a process identity nor a clock. A later
upgrade coordinator chooses and authenticates those inputs; this foundational
primitive merely persists the first successful invocation exactly. A replay
with different supplied provenance preserves the recorded row unchanged.

Applying the catalog is separate from normal `Store::open` and runs only on the
retained store-owned connection inside one `Immediate` transaction. It must
check every existing ledger row against the complete compiled catalog before
applying a missing entry: unknown, duplicate, newer, missing-required, or
wrong-checksum history, and an incompatible ledger table, fail closed without
new schema or ledger mutation. An exact already-recorded entry is a no-op.
Every explicit transaction completion result is checked; a rollback, finish,
or commit failure poisons the retained store connection and future migration
calls fail closed until a fresh profiled `Store::open`. This primitive creates
no domain table or operational schema.

Every row that references a MAC key stores the resolvable `MacKeyRef` in the same four columns: a closed
`purpose u8`, an `origin BLOB(32)` holding the `OriginIncarnation`, and a `serial_hi`/`serial_lo` pair of
`0..=4294967295` `INTEGER` limbs (per the limb rule below; `(0,0)` is invalid). These columns are
`NOT NULL`, and each carries a row-local `CHECK` that the stored purpose equals the column's declared
purpose, so equal `MacKeyId` values under different purposes are valid and resolve to distinct paths. No
surrogate integer key is used in a referencing row: a surrogate could be reassigned across the restore
merge and reintroduce the collision this model removes. The ring manifest row inside each state generation
additionally stores `status` and `created_at`, and its key-file relative path is exactly
`mac/<purpose-2-lowercase-hex>/mk_<80-lowercase-hex>`, derived only from the table bytes, never from
display text or enum order. The authenticated MAC input is the literal 40 `MacKeyId` bytes at fixed width
with no length prefix.

Payload is three canonical JSON blobs (`destination`, `content`, optional `options`) plus kind/version
columns for indexed validation. SQLite is not application-layer encryption; file/directory/backup
protection is mandatory. Raw `idempotency_key`, `correlation_id`, replay key, and every `command_key`
class identifier are never stored in SQLite or the fixed journal. Only purpose-separated keyed digests,
digest-key versions, and safe generated references persist; drain, admission, generation, and recovery
records follow the same rule. Addressed-state shutdown retains only its opaque generated process
instance and typed phase/result, never a caller key.

Every guarded generation and receipt prior/result generation is stored as two nonnegative SQLite
`INTEGER` limbs `(hi, lo)`, each constrained to `0..4294967295`; Rust reconstructs one `u64` only after
both checks. Zero `(0,0)` is invalid. Database checks encode increment exactly: `lo < 4294967295`
requires `(result_hi, result_lo) = (prior_hi, prior_lo + 1)`, while `lo = 4294967295` and
`hi < 4294967295` requires `(prior_hi + 1, 0)`; `(4294967295,4294967295)` cannot produce a result. This
avoids passing values above `i64::MAX` through rusqlite's signed `INTEGER` conversion while retaining the
full public `u64` domain.

Each generation-guarded receipt is a fixed nullable column group adjacent to its owning row, not a
history table: exact 32-byte resource incarnation, prior/result generation limbs, actor namespace,
closed operation/desired-state/reason fields, and safe result reference. All-or-null checks apply to the
group. Row-local database checks enforce the increment relation above, nonzero generations, and receipt
incarnation equality with its adjacent owning resource incarnation; the owning current generation must
equal the receipt result before it can satisfy recovery. Staged-transition and startup invariant checks
require every live resource incarnation to equal the selected meta history epoch before readiness. A
principal command-key update advances the principal generation without replacing the guarded receipt,
making that receipt ineligible immediately. Grant
absence is representable because its single receipt lives on the principal's grant collection rather
than on the optional pair row. Ordinary continuation and restart preserve the exact pair. Restore and
rollback allocate a new history epoch/resource incarnation, apply quarantine or rollback truth, then
reset all surviving guarded generations to `(0,1)` and receipts to null before selection; no old branch
receipt or numeric generation can revive authority.

<!-- incarnation-allocator-contract:start -->
The fixed-root branch-incarnation allocator is the sole authority for a new history epoch. It has no
per-branch random-ID fallback and obeys all of these closed rules:

1. Wire construction MUST be exactly
   `ResourceIncarnation = OwnerNamespace[24] || BranchSerialBE[8]`; the serial MUST be encoded as an
   unsigned nonzero big-endian `u64`, and the concatenated 32 bytes MUST retain the canonical
   64-lowercase-hex wire.
2. Namespace derivation MUST be exactly
   `OwnerNamespace = Truncate192(HMAC-SHA-256(host_local_journal_key, "msgriver/resource-incarnation-namespace/v1"))`.
3. The allocation registry MUST be exactly `bootstrap.create`, `restore.create`, and `upgrade.rollback`;
   every other operation MUST NOT allocate or advance a branch serial.
4. The authenticated fixed-root journal header MUST own `owner_namespace` and
   `branch_serial_high_water`. A new header MUST start at zero, MUST recompute the namespace from the
   final journal key, and MUST reject any stored namespace/key mismatch before a usable root or selected
   state.
5. The first durable transition intent for an allocating operation MUST atomically advance and burn
   exactly one serial in the same authenticated replacement image; there MUST be no crash-visible state
   in which an intent exists without its advanced high-water or vice versa.
6. That allocator intent MUST bind the operation/transition kind, allocated serial and complete target
   incarnation, source generation/incarnation, typed parent epoch/head/certificate inputs, and command
   fingerprint before any staging directory, generated state, or active pointer MAY exist.
7. Allocation MUST use checked `u64` arithmetic: zero MUST NOT be issued, carry MUST be exact, and a
   high-water of `u64::MAX` MUST return `state_incarnation_unavailable` without wrap or a new intent.
8. Recovery of the same authenticated nonterminal intent MUST reuse its exact serial and target bytes;
   it MUST NOT advance again, MUST NOT choose another target, and MUST NOT reroll after a crash or
   collision.
9. Every allocated serial MUST remain burned when staging aborts or terminally fails; deletion,
   cleanup, rollback, restart, and journal compaction MUST NOT decrement or reclaim the high-water.
10. The continuation registry `configuration.activate`, `state_key.rotate`, `state_key.retire`,
    `upgrade.migrate`, `upgrade.activate`, and forward repair MUST preserve the complete incarnation and
    MUST perform no allocator write.
11. Request bodies, backup artifacts, selected SQLite state, environment variables, configuration,
    generated IDs, hidden defaults, and CLI flags MUST NOT supply or override the namespace, serial,
    complete target incarnation, or allocator high-water.
12. Before generation staging, the allocator MUST check the target against the active pointer, retained
    history epochs, retained sibling/parent provenance, every nonterminal intent, and identifiable
    staged-generation metadata. A collision, source/parent mismatch, or target/serial mismatch MUST
    return `state_incarnation_unavailable` in bounded work without selection or pointer mutation.
13. Same-root non-reuse MUST be deterministic from the authenticated monotonic high-water and MUST NOT
    depend on retaining an unbounded set of prior branches or receiving distinct per-operation random
    values.
14. Cross-host non-reuse MUST rely on independently generated host-local journal keys and the
    computational collision security of the 192-bit truncated HMAC namespace; this is an explicit
    cryptographic assumption, not a deterministic observation of disconnected machines.
15. Copying or importing a fixed owner root or its journal key into concurrently live hosts MUST remain
    unsupported. A blank host cannot prove that a namespace was never used only by an unrelated,
    disconnected host, and the API MUST make no stronger claim.
16. Exact same-command recovery and an existing restore/upgrade hold that forbids a fresh transition
    MUST resolve before allocator evaluation. A transition permitted through its own hold MUST validate
    the allocator before clock evaluation, so a combined serial-maximum/clock-hold case MUST return
    `state_incarnation_unavailable` without clearing the original hold.
17. Fresh allocator validation MUST be nonmutating. A transition permitted through its own hold MUST
    return an allocator failure before `clock_hold` when allocator state is its immediate blocker. With
    no pre-existing safety hold and usable allocator state, clock evaluation MUST precede fixed-root
    control-capacity projection plus admission, drain, and coordinator-conflict disclosure; capacity
    admission then MUST precede publishing and burning the allocating intent. Thus serial maximum plus
    clock/capacity MUST return `state_incarnation_unavailable`, usable serial plus clock/full capacity
    MUST return `clock_hold`, and usable serial without clock plus full capacity MUST return
    `control_capacity`; none publishes or burns an intent.
18. A `local allocator witness` MUST be exactly a selected pointer or current guarded-resource
    incarnation, a locally issued target field in an allocating intent, an identifiable locally staged
    target, or a history/provenance epoch allocated by this owner root. Every local allocator witness
    MUST carry the recomputed namespace and a serial at or below the authenticated high-water.
19. Foreign authenticated ancestry MAY be retained only as immutable ancestry reachable through one
    authenticated blank-restore boundary whose artifact head and lineage chain verify under the
    artifact recovery trust. It MUST NOT be a local allocator witness, MUST NOT become a selected
    pointer or current guarded-resource incarnation, MUST NOT supply local high-water evidence, and
    MUST NOT authorize a request or receipt. A MAC key whose `OriginIncarnation` is foreign (an
    `imported_key_origin` under R3-INV-109) is likewise not a local allocator witness and supplies no
    selected-origin purpose-local high-water evidence. For this rule, `one` means the current selected
    owner root's immediate boundary; earlier authenticated blank-restore boundaries carried inside that
    verified artifact lineage MUST NOT count against the current root's boundary, and every epoch
    behind it remains foreign.
20. At branch-serial exhaustion, the supported recovery MUST be a new independently keyed blank owner
    root plus authenticated disaster restore of a previously valid artifact. The exhausted owner root
    MUST NOT be re-keyed in place, and restore MUST allocate serial one under the new namespace rather
    than rewriting or adopting any artifact-era incarnation.
21. Serial exhaustion alone MUST NOT block delivery, authorized status, exact command/result recovery,
    or `configuration.activate`, `state_key.rotate`, `state_key.retire`, `upgrade.migrate`,
    `upgrade.activate`, and forward repair. Those operations remain subject to their independent
    authorization, hold, durability, and capacity rules but MUST perform no allocator write.
22. The closed readiness reason for a fixed-root serial at `u64::MAX` MUST be
    `incarnation_exhausted`; it MUST be derived exclusively from the authenticated persisted
    `branch_serial_high_water`, and the rejected allocating operation and a readiness read MUST NOT
    perform a readiness or allocator write. A-15.3 owns its safe CLI, JSON, and metrics representations.
<!-- incarnation-allocator-contract:end -->

`operation_commands` is the generic SQLite authority for every catalog `command_key` or
`one_time_secret` operation whose authoritative effect is in selected state. Its unique scope is
`(operation_id, actor_namespace, command_key_origin, command_key_serial_hi, command_key_serial_lo,
command_digest)`; source runtime/process is data,
never part of uniqueness. After current authentication, lookup computes the bounded retained command-MAC
key ids. A matching current-runtime record accepts only its frozen semantic fingerprint or an
operation-declared phase transition, rechecks current authorization, and returns the safe phase/result.
An incompatible fingerprint returns `command_conflict`. A matching foreign-runtime record returns
`command_namespace_changed` until its terminal half-open expiry; it can never authorize a result or new
effect. On a miss, the store transaction rechecks current authorization/admission, commits the
authoritative effect and command row together, and releases no response beforehand. A terminal record
sets `command_expires_at = terminal_safe_at + configured_command_window`; null is reserved for a
continuation that still owns authoritative phase state and cleanup cannot remove it. At the exact
terminal boundary, its result/reservation/key-dependency projection becomes logically absent. Normally,
physical deletion and a newly authorized effect occur in the same transaction. During A-10.7's rollback-
eligible phase, the store derives that absence from validated safe time and the immutable expiry without
writing the frozen generation: same-key lookup discloses no result and becomes a prohibited fresh
mutator, so it returns `upgrade_activation_pending`. Before lookup first exposes a crossing above
A-11.5's effective durable high-water, the allowed checkpoint/mirror makes the proof durable; if it
cannot, lookup fails unavailable and does not fall back to the old row. Proven expiry is monotonic, so a
later clock hold never restores result, conflict, namespace, reservation, or MAC-key authority. The
final activation, rollback-clone, or forward-
repair transaction deletes every logically expired selected row before clearing holds. Command MAC keys
and semantic canonicalizers remain usable through every physical cleanup and null continuation.

For operations that durably create a coordinator/job/resource, creation plus its generated ID is the
command's terminal-safe effect even while the independently queryable resource progresses. For
single-phase API-key issue/rotation, key-row creation, one-time serialization state, safe result
metadata, and command record commit atomically before plaintext bytes are attempted; retries never
redisclose plaintext. Fixed-root operations use the equivalent A-13.2 record and mirror safe evidence
into SQLite only after selection; the fixed journal remains authoritative across a cross-store crash.

Every fixed-root record additionally carries a purpose-separated portable reservation digest. Its MAC
generation is distinct from the host-local journal-integrity/key-digest key: a portable match can only
reserve the `(operation, actor, caller-key)` tuple and produce `command_namespace_changed`, never
authenticate a journal record or return its result. Before bootstrap, the fixed root creates this
portable key with the journal and records both digests. Bootstrap copies the portable key generation and
unexpired/null reservations into the first selected state. Thereafter maintenance reads the bounded
portable key ring from selected state before its first fixed-root effect. Those key generations and rows
are part of the artifact's recovery-key-encrypted state section and remain through every reservation
expiry/null continuation; raw caller keys remain absent.

Every transaction that changes restore-comparison truth appends one batch atomically with that change.
It increments the gapless comparison batch sequence, assigns event ordinals exactly `0..event_count-1`,
and computes
`SHA256("msgriver-restore-comparison-v2" || history_epoch_id || batch_sequence ||
source_transaction_sequence || event_count || previous_batch_digest || epoch_boundary_fields ||
canonical_events)` over fixed-order encodings. The batch header,
all events, and new meta head commit with the authoritative state transition. Events include acceptance,
dispatch/effect uncertainty, known provider acceptance, terminal state, and payload-purge/tombstone
changes. Generated IDs and closed flags are sufficient to construct the immutable report after ordinary
message/audit rows expire; a purge event additionally contains exactly the generated message ID, durable
purge instant, and closed source/reason stored in its tombstone. Caller content, destination, raw
identity, and provider data are forbidden.

The closed `restore_comparison_events.lifecycle_event` vocabulary is exactly, as ASCII text: `accepted`, `dispatch_marked`, `ambiguity_recorded`, `provider_accepted`, `failed`, `cancelled`, `expired`, and `payload_purged`. Each value is the projection of one already required store mutation, and these mutations are the complete set of relevant mutations for the meta-head tripwire: a `messages` insert appends `accepted`; the A-09.3 dispatch-mark transaction appends `dispatch_marked`; a fenced, stale, or lease-recovery transaction that records an ambiguous attempt outcome or raises `duplicate_effect_possible` from 0 to 1 appends `ambiguity_recorded`; a `messages.state` change to `provider_accepted`, `failed`, `cancelled`, or `expired`, including the sole late-acknowledgement terminal promotion, appends the event named by the new state; a `purge_tombstones` insert appends `payload_purged`. No other mutation (`held`, `retry_scheduled`, `cancel_requested`, lease, deferred-outcome, idempotency, audit, or retention cleanup) changes restore-comparison truth or appends an event. Every event carries `message_id`; `dispatch_marked`, `ambiguity_recorded`, and `provider_accepted` also carry `attempt_id`. `terminal` is 0 for `accepted` and `dispatch_marked`, 1 for the four terminal-state values and `payload_purged`, and the row's current terminality for `ambiguity_recorded`; `effect_may_have_occurred` is 1 for `dispatch_marked`, `ambiguity_recorded`, and `provider_accepted`. Only `payload_purged` carries the non-null purge projection, with `purge_message_id = message_id`; every other value carries it null. An epoch boundary is represented only by batch-header boundary fields and is never a `lifecycle_event`.

The closed `purge_source` vocabulary, identical in `purge_tombstones` and `restore_comparison_events`, is exactly `operator` and `maintenance`. The closed `purge_reason` vocabulary is exactly `operator_request` (PR-117 immediate purge), `accepted_retention` (the A-10.6 one-minute post-acceptance purge), and `dead_letter_retention` (the A-10.6 configured `failed`-payload retention, including a zero window). `operator` pairs only with `operator_request`; `maintenance` pairs only with the two retention reasons.

Bootstrap allocates the first structured 256-bit history epoch, which is also the guarded-resource
incarnation. Ordinary state/generation continuation keeps that epoch. A restore or rollback that
creates a new logical branch allocates the next structured epoch/incarnation whose
first typed boundary batch binds the exact prior selected epoch/head/digest (or, for blank restore, the
artifact head and `comparison_unavailable` origin). The fixed control journal and HMAC-authenticated
active-state pointer certificate bind generation ID, lineage ID, current history epoch, and origin
transition ID under the host-local journal key; the selected database mirrors that certificate digest.
Startup and every staged clone verify the pointer certificate before trusting comparison rows. A source
chain must end in the source pointer's authenticated epoch before copy, every epoch change must be one
typed boundary whose parent equals the preceding head, and the staged chain must end in the target
pointer's epoch after activation. A complete valid sibling suffix therefore fails before it can become
the source for a new boundary.

The typed boundary of a first epoch batch is the four-column group `boundary_parent_history_epoch_id`, `boundary_parent_batch_sequence`, `boundary_parent_batch_digest`, and `boundary_parent_origin` on `restore_comparison_batches`, all null or all non-null. `boundary_parent_origin` is closed ASCII text: `selected_head` when the parent tuple is the exact prior selected epoch/head/digest (proven nonempty restore and `upgrade.rollback`), or `comparison_unavailable` when the parent tuple is the authenticated artifact head of a blank-state restore. `comparison_unavailable` is valid only on the first batch of an epoch whose `history_epochs.origin_transition` is `restore`; the bootstrap epoch's first batch has a null group. The four boundary columns in that order are the `epoch_boundary_fields` of the batch digest, so the marker is digest-bound and authenticated with the chain. A-10.2 rule 19's authenticated blank-restore boundary is exactly a batch with `boundary_parent_origin = 'comparison_unavailable'`.

The retained prefix is represented by one anchor `(history_epoch_id, batch_sequence, batch_digest)` and every retained
batch must continue at exactly anchor+1 through the meta head, match its predecessor digest, contain its
declared ordinals/count, and recompute its digest. Prefix compaction may advance the anchor only when no
unexpired `backup_history` row and no nonterminal `backup_jobs` running pin protects an earlier head; it
never deletes a middle/tail batch. Event
references are immutable generated values without cascading foreign keys to expiring message/audit rows,
so ordinary cleanup cannot erase them indirectly. Store mutation helpers require a comparison batch for
every state transition named above; schema triggers/test-only tripwires reject a relevant mutation that
does not advance the head.

For every proven restore, the authenticated artifact image supplies the exact base tombstone projection
at its watermark, including a canonical count/digest. Verified events from artifact head+1 through the
selected live head supply the exact suffix projection. The set union must equal current
`purge_tombstones` rows by message, instant, reason, epoch, batch, and ordinal: a pre-snapshot row cannot
be demanded from a compacted suffix, and a post-snapshot row cannot be trusted from the current table.
Schema constraints/triggers reject a purge row without its same-transaction event and reject mutation/
deletion of either side; indefinite v1 row retention preserves the union after old event-prefix
compaction.

#### A-10.2.2. Active-state pointer certificate mirror

The singleton `meta` row contains exactly `active_state_pointer_certificate_digest BLOB NOT NULL CHECK(typeof(active_state_pointer_certificate_digest) = 'blob' AND length(active_state_pointer_certificate_digest) = 32 AND active_state_pointer_certificate_digest <> zeroblob(32))`. It is initialized from the authenticated pointer digest before sealing and is immutable thereafter: update or replacement of the singleton cannot rebind a completed generation. Using only the candidate descriptor covered by sealed-image evidence, the coordinator performs exactly `SELECT active_state_pointer_certificate_digest FROM meta WHERE singleton = 1`; exactly one nonzero 32-byte BLOB byte-equal to the authenticated digest yields only a private nonterminal fact, and every failure/mismatch rejects it.

### A-10.3. Core constraints and indexes

- Unique active idempotency key: `(principal_id, lookup_key_origin, lookup_key_serial_hi,
  lookup_key_serial_lo, lookup_digest)`.
- Unique attempt ordinal per message and unique fence generation per message.
- Unique replay request per `(actor_principal_id, replay_key_origin, replay_key_serial_hi,
  replay_key_serial_lo, replay_digest)`.
- Unique operation command per `(operation_id, actor_namespace, command_key_origin,
  command_key_serial_hi, command_key_serial_lo, command_digest)`;
  runtime identity is deliberately excluded so a restored namespace collides safely instead of
  repeating an effect.
- Unique restore-comparison batch sequence with strict predecessor `head + 1`; unique event per
  `(batch_sequence, event_ordinal)`, exact ordinal count, immutable epoch membership, typed boundary
  uniqueness, an all-null or all-non-null `boundary_parent_history_epoch_id`, `boundary_parent_batch_sequence`, `boundary_parent_batch_digest`, and `boundary_parent_origin` group on a first epoch batch, closed `boundary_parent_origin` values `selected_head`/`comparison_unavailable`, and an index by generated command/message ID.
- Store-actor prospective-state checks plus schema triggers on principal and peer-mapping mutations
  require at least one enabled UID-0 mapping to an enabled operator principal with an operator ceiling
  in every committed selected state; bootstrap/restore seed it and direct/helper mutations cannot bypass
  `last_local_operator`.
- Message state `CHECK` constraints require/forbid lease fields, terminal time, hold reason, and known
  acknowledgement consistently.
- `effect_may_have_occurred` and `duplicate_effect_possible` have monotonic update triggers/guard SQL;
  application transition code cannot write false over true.
- Eligible index: `(state, next_attempt_at, provider_id, owner_principal_id, created_sequence)`.
- Ownership list index: `(owner_principal_id, created_sequence, message_id)`.
- Purge/retention indexes use terminal/payload/idempotency expiry times.
- Foreign-key deletion is restricted for message/principal/provider history; retention redacts fields
  instead of cascading truth away.

The test suite introspects schema SQL and query plans for the invariant constraints and critical
eligible/list paths.

### A-10.4. Enqueue transaction

After authentication, bounded decoding, the reserved idempotency pre-pass, and disk-budget preflight,
one `BEGIN IMMEDIATE` transaction:

1. recomputes all bounded lookup digests for active MAC key versions and rechecks an unexpired
   idempotency record before any current admission condition;
2. if no record exists, rechecks authorization epoch, principal enabled/scopes, provider grant/current
   generation, and admission/clock/restore/upgrade/storage holds;
3. validates/pins the current connector identity and credential/config availability;
4. if found, constant-time compares semantic fingerprint and returns existing result or conflict;
5. removes an exactly expired mapping for that scope/key while preserving historical message metadata;
6. rechecks global/principal/public-provider/private-connector-identity message+byte/rate quota and the
   complete storage-reserve snapshot;
7. increments transaction/created sequence;
8. inserts message, initial audit/status, and idempotency mapping atomically;
9. commits under `synchronous=FULL` and only then releases a fresh response.

Any error rolls back every row. The actor response type distinguishes committed-fresh,
committed-existing, conflict, admission, and unavailable; API code cannot infer commit from a generic
error string.

### A-10.5. Attempt transactions

Claim selects one eligible pair using A-11 and atomically updates exactly one message plus attempt row.
Dispatch mark and outcome use A-09 fencing. No transaction spans connector I/O. A failed outcome commit
is loud: the worker retains no authority to retry the SQL blindly after its fence could expire; it
reports to the coordinator, which degrades readiness and lets normal lease recovery arbitrate.

### A-10.6. Cancel, purge, replay, and retention

- Cancel updates queued/held/retry work terminally, or only sets `cancel_requested` on delivering work.
- Purge first requires a terminal message; a non-terminal target returns `message_not_terminal` without
  mutation. If that terminal message is already purged, it returns the original safe purge result and
  tombstone as an idempotent no-op without a new comparison event or transaction-watermark change.
  Otherwise it nulls three payload blobs and byte charge, inserts the tombstone, and marks payload
  unavailable in one durable transaction. It makes no raw-page erasure claim.
- Replay first resolves operator replay idempotency, locks the source row, rejects absent payload/non-
  dead-letter/expired retention, validates current provider/schema policy and the original owner's
  enabled state plus current provider grant, and in the same transaction rechecks operator admission
  plus every clock, storage, restore, upgrade/quiescing, drain, and shutdown hold under fresh-effect
  precedence. Only then does it insert child, replay mapping, and audit. The operator actor's scope and
  reserved control capacity never substitute for owner state/grant or bypass a closed admission/hold.
  The child retains the original owner and
  consumes that owner's outstanding/rate/byte quota; operator control reserve permits reaching the
  transaction but does not bypass owner/provider admission limits. It inherits
  `duplicate_effect_possible = parent.effect_may_have_occurred OR parent.duplicate_effect_possible`.
- Maintenance purges provider-accepted payload after one minute, failed payload at configured retention,
  and expired idempotency/terminal operation-command mappings at their half-open boundaries in small
  bounded batches. Terminal command authority expires logically at the exact boundary even when
  physical removal is deferred by A-10.7's rollback freeze and its generated resource remains: result/
  reservation lookup treats it as absent, while resource, generation, ring, rollback, and artifact
  dependencies are separate generated-ID provenance. A
  null-expiry command is never an age-cleanup candidate.
- Safe terminal metadata defaults to seven days; audit/backup history limits are independently bounded
  in architecture configuration and documented before release. The explicit
  `nonempty_restore_support_window` defaults to 30 days and is capped at 365 days in v1; each completed
  backup freezes its own deadline, and later configuration changes cannot shorten it. Provenance and
  history epochs/comparison batches/events remain until every deadline that depends on them has passed.
  Cleanup computes the oldest unexpired provenance epoch/batch head before advancing the digest anchor,
  then deletes only the verified prefix and unused epoch records through that anchor in the same store-
  actor transaction. Purge tombstones are
  retained indefinitely in v1 (or until a future release proves they outlive the oldest supported
  backup); they are not deleted with ordinary terminal metadata.

### A-10.7. Migration policy

Migrations are embedded, ordered, checksum-pinned SQL plus explicit Rust data transforms. They are not
an invisible side effect of normal startup. `upgrade.prepare` is a durable, connection-independent
coordinator with a pre-eligibility `quiescing` phase. After exact same-command recovery and resolution
of any pre-existing restore/upgrade hold, and before creating it, the store actor authenticates the
fixed-root header and atomically requires `branch_serial_high_water < u64::MAX`. At MAX it returns
`state_incarnation_unavailable` before coordinator, hold, operator-admission, journal, or allocator
mutation. At MAX−1 it may proceed: no allocating operation can interleave before phase exit, so rollback
may burn MAX exactly once and exact same-command rollback recovery remains available at MAX. With
usable serial headroom and no pre-existing safety hold, A-11.5 clock evaluation precedes nonterminal-
drain and capacity disclosure: a clock hold returns exact `503 clock_hold` with null retry hint;
otherwise a drain that serialized first returns `409 drain_in_progress` with no prepare state/hold. A
prepare that serialized first makes later `drain.start` fail under its hold. Still before the first
coordinator or hold, the actor acquires the transition gate and journal-publication lock, revalidates
A-11.5's pre-existing-hold, header, serial, clock, drain, pointer, and plan facts, and computes the
canonical `upgrade_exit_capacity_binding`. The reserved total is prepare's own fixed-root command
record plus the sum of maximum encoded bytes and entries for exactly four protected phase roles: one
complete-plan `upgrade.migrate`, one ordinary `upgrade.activate`, one dedicated `upgrade.rollback`, and
one `upgrade.activate` forward repair, plus the maximum shared divergence, resolution, and lasting-
provenance projection. Each role maximum contains its complete command, portable reservation, intent,
result, allocator, and role-local provenance. This conservative sum explicitly includes migrate →
rollback serial burn → authenticated mismatch → durable divergence → forward repair; consuming the
rollback role cannot remove the repair role or shared projection. If the complete bound cannot fit the
ordinary checkpoint entry or byte limit, prepare returns `503 control_capacity` before fixed-root
intent, coordinator, hold, operator-admission, journal, or selected-state mutation.

One authenticated fixed-root prepare-intent publication makes the binding durable before the selected
coordinator transaction. Its plan digest, fixed-root journal format, framing, MAC-key format, per-role
codec versions, per-role entry/byte maxima, consumed-role bitmap, reserved total, and release condition
are part of the checkpoint projection and open-upgrade transcript. A continuation binary must support
and write that exact bound format; an incompatible version fails before role consumption and leaves
compatible continuation or rollback authority intact. Every
unconsumed reserved byte and entry is charged as occupied for unrelated ordinary admission; the
reconciliation reserve cannot satisfy or be borrowed into the bound. A protected phase command
atomically converts only its named reservation into actual projection and does not repeat ordinary-
capacity admission. Exact same-command recovery reuses that conversion, a different key cannot reuse a
consumed role, and migrate, ordinary activation, or forward repair can never consume the dedicated
rollback role. Folding preserves the binding semantically and cannot shrink, discard, or reassign it.
Before the watermark, prepare failure clears its selected coordinator and then releases unused binding
in the terminal fixed-root publication. After the watermark, unused binding is released only when the
selected-state activation, rollback, or forward-repair mirror is durable and the fixed root records the
same phase exit; a crash selects the bound open phase or the complete released terminal, never an open
phase without its bound.

Every rollback source, plan, capacity, allocator, certificate, and witness validation that can reject
runs before its allocator transaction burns the serial. Once burned, a filesystem or durability prefix
remains nonterminal and exact same-command recovery must finish it using the bound rollback role. An
authenticated state mismatch appends the bound `upgrade_diverged` provenance and retains the bound
forward-repair role. No ordinary rollback outcome may terminalize while rollback eligibility remains
open unless one of those exact recovery paths remains durable. Its
first FULL transaction records the coordinator and exact prior operator-admission intent, closes new
submission and A-10.6 replay child creation through a separate prepare hold without changing the
operator-admission row, closes scheduler/provider dispatch and `backup.create`
admission, snapshots every admitted backup coordinator's immutable execution deadline, component
maxima/margins, and same-boot monotonic mirror from its durable job row, and leaves
already-dispatched fenced invocations as the only delivery mutations still allowed. Those invocations
apply A-09.2's total order. Known acceptance commits normally; any other outcome with a decisive
cancellation, expiry/max-age, or exhaustion guard terminalizes in that transaction; absent such a guard,
permanent truth becomes `failed`, while transient/rate-limited/configuration/authentication/ambiguous
truth becomes `held` with `hold_reason = upgrade_quiescing`, its closed deferred outcome class and
bounded relative hint, and null message/circuit deadlines. Later cancellation records
`cancel_requested`, and autonomous expiry/max-age/attempt maintenance excludes that held row. Deferred
authentication/configuration truth appears immediately in connector health as `quiescing_deferred`.
No new lease or external invocation may start after that first commit. A backup already
admitted may only run its A-14.1/A-14.2 publication or
startup-reconciliation automaton to exactly one durable `complete`, `failed`, or `cancelled` terminal
state; no other backup operation starts, and no half-published job may cross the prepare watermark.
The same store-actor serialization governs `admission.set`. After authentication and authorization, an
exact actor/closed-semantics/complete-address match against the still-current incarnation-bound guarded
receipt, or a complete expected-current desired-state match, returns the existing tuple as a read-equivalent no-op before
any restore, upgrade, clock, admission, drain, or coordinator hold/conflict check in every phase. Any
other incarnation/generation mismatch returns `state_generation_conflict` without changing the tuple,
receipt, or coordinator. Only a complete expected-current different value is a fresh mutator. If
committed before the first prepare transaction, its state, incremented generation, and replacement
receipt become the exact saved tuple; a
different value ordered afterward returns `409 upgrade_prepare_in_progress` until either
`prepare_failed` or the successful prepare-watermark transaction commits. A different value ordered after failure observes and may
mutate restored terminal truth; after a successful watermark it is prohibited by
`upgrade_activation_pending` until activation, rollback, or forward repair ends that phase.

At that first transaction the coordinator samples validated safe time and persists one immutable safe-
UTC prepare deadline, its exact component maxima/margins, and a same-boot monotonic mirror. The deadline
is the maximum of every remaining provider invocation hard deadline, every remaining persisted dispatch
`lease_expires_at`, and every admitted backup coordinator's remaining immutable job execution deadline,
plus the
configured fence-recovery, backup-reconciliation, and outcome-commit margin. Restart reconstructs a
conservative monotonic remainder from that UTC deadline and authenticated safe-time high-water without
moving the deadline later; clock uncertainty leaves the stricter hold. The lease term is
not replaced by the shorter connector timeout: after a worker crash, recovery waits for the persisted
lease boundary, arbitrates the fence, and commits explicit ambiguity/outcome truth before proof. For the
final proof it acquires the fixed-owner transition gate and journal-publication lock, then under the
store actor proves there are zero dispatching leases, zero external invocations, no uncommitted
outcome/cancellation token, and no nonterminal backup coordinator, and rechecks the selected pointer.
A committed `upgrade_quiescing` row is quiescent evidence, not eligible work. Its sole release is the
normal-outcome projection under the store actor. Known acceptance was already terminalized; at then-
current validated safe time, a retained cancellation wins, then expiry/max-age, then attempt
exhaustion. Otherwise `Transient`, `RateLimited`, and `Ambiguous` invoke the persisted-reference jitter
derivation: unavailable/exhausted source changes the row to `retry_jitter_unavailable` with every deadline
null and retained deferred evidence; only a successful derivation becomes `retry_scheduled` with one
conservative `next_attempt_at` derived from deterministic backoff and the retained bounded relative hint;
ambiguity remains sticky. `AuthOrConfig` follows the same source result: only successful derivation
receives the bounded message deadline and atomically opens the connector-wide circuit with one
conservative probe `not_before`, so queued messages cannot each probe. That circuit record is absent
while safe-time projection is deferred or jitter is unavailable, but connector health exposes the retained
class. The projection clears the deferred fields and upgrade hold only on successful jitter derivation,
and otherwise replaces only the upgrade label with `retry_jitter_unavailable`; it appends one hold-cleared
audit event in the same FULL transaction. If a clock anomaly
prevents safe-time derivation, that transaction instead changes the reason to `clock_anomaly`, retains
the deferred evidence with every message/circuit deadline null, and leaves A-11.5 as the only release.
No row is ever made eligible merely by clearing a coordinator flag. Only the following FULL
transaction may record the exact source generation, transaction/effect/comparison heads, named
completed backup and its watermark, upgrade/target IDs, and the fixed-journal head and change phase to
`prepared`. That transaction is the prepare watermark and the first instant at which the sealed source
is rollback-eligible. If the proof is unavailable at the frozen deadline, no watermark/source exists.
As soon as the store can commit, one FULL `prepare_failed` transaction records the stable
`upgrade_quiescence_unproven` result, restores the exact prior operator-admission intent, and clears only
the coordinator's admission/dispatch/backup holds. In that same transaction it applies the projection
above to every `upgrade_quiescing` row, or converts those rows to the stricter clock hold; it never
clears a clock, storage, restore, or integrity hold or releases an unresolved lease. Startup runs this
coordinator before readiness and terminalizes an elapsed interrupted failure idempotently. Same-key
retry returns the terminal failure; only a fresh key
may begin another preparation after ordinary recovery. With the daemon stopped, maintenance `upgrade.migrate`
copies only a successfully prepared active generation, applies one checksum-pinned migration
transaction at a time, runs foreign-key/integrity checks, fsyncs the complete new generation, and
atomically points to it using A-14.3. The new binary starts held for local read-only smoke.

The successful prepare transaction opens one rollback-eligible read-only phase that ends only at
`upgrade.activate`, `upgrade.rollback`, or an explicit successful forward repair. The sole store actor
owns the durable phase and registry truth: it freezes the exact fixed-root-authoritative internal
lifecycle registry of A-13.2—`clock.checkpoint`, exact-observation `clock.acknowledge`, and
`system.shutdown`—as the only internal lifecycle set admitted during the phase, and its schema guards
enforce that phase rather than relying on UI discipline. Daemon dispatch owns only per-binding route
reachability; during the phase it admits safe reads, authenticated committed-result lookup,
health/readiness, `upgrade.show`, `upgrade.migrate`, `upgrade.activate`, and `upgrade.rollback`, each only
on its cataloged binding, plus exactly that store-owned internal lifecycle set and nothing else. Every
other selected-state mutator returns
`409 upgrade_activation_pending`; autonomous expiry, purge, command cleanup, scheduler/lease transitions,
provider outcomes/effects, retries, backups, drains, admission changes, identity/grant/key/configuration
changes, restore, cancellation, and state-generation deletion do not start. Smoke consists only of
integrity/schema/key-reference checks and safe API/probe reads. A terminal command crossing its
authenticated half-open expiry is a derived logical absence rather than selected-state cleanup. Before
lookup first reports that absence, an allowed `clock.checkpoint` durably raises the relevant
authenticated high-water and mirrors only clock authority; publication failure returns unavailable
without stale disclosure. Physical bytes remain inert until the chosen hold-clear transaction prunes
them under A-10.2/A-13.2, and a later clock anomaly cannot lower that proof or revive authority.

The A-13.2 journal gives every publication a gapless `journal_sequence`, previous digest, record digest,
and HMAC-authenticated checkpoint/tail projection. Prepare binds its exact head and initializes the
open-upgrade transcript accumulator. Migration validates the checkpoint plus tail after that head:
upgrade records must match the migration phase automaton, while every interleaved record must belong to
the exact three-record A-13.2 lifecycle registry. If raw records have folded, their ordered count/digest
and current deterministic mirror state come from the authenticated open-upgrade projection; retained
tail records extend that same accumulator. Migration mirrors the resulting projection idempotently,
finalizes the candidate, and freezes the resulting `migration_lifecycle_commitment` (count, transcript
digest, last sequence/digest, and mirror digest). Lifecycle mirrors may advance only the target's exact
transaction/audit and clock/shutdown-result fields. Explicit `clock.acknowledge` and an event-triggered `clock.checkpoint` that
commits automatic settlement both mirror the fixed-root clock authority plus
`deadline_derivation_pending`, never message, circuit, scheduler, retry, lease, cleanup, or expiry
deadlines. The mirrors append no restore-comparison event because they do not change the delivery/
comparison truth defined by A-10.2.

Before activation, rollback-clone selection, or forward repair freezes the checkpoint/tail head for its final
hold-clear path, it proves that every caller-key boundary it will delete or exclude from the fixed-root
projection is at or below A-11.5's effective durable high-water. A newly observed crossing first appends
the allowed `expiry_proof` checkpoint and required mirror, then restarts projection validation; failure returns
durability unavailable without deletion, stale disclosure, pointer change, or hold clear. The final
transaction compares only against that durable proof, never then-current uncommitted wall time.
The same validation snapshots the durable operator-admission tuple `(state, incarnation, generation,
actor, reason, changed_at)`. Activation and forward repair clear only upgrade/quiescing safety holds and
must preserve that tuple byte-for-byte. Rollback preserves its selected value/actor/reason/time but, as
a new branch, installs its intent-bound allocated target history epoch as the new incarnation, resets generation to one, and
clears the receipt before selection. Any other attempted or observed admission change is an unexpected
selected-state delta and follows the divergence path rather than implicitly opening ingress.

`upgrade.activate` acquires the transition gate and journal-publication lock before examining state. It
snapshots the current checkpoint plus tail and extends/verifies the frozen
`migration_lifecycle_commitment` under the same closed rule, proves that the selected target,
host-authenticated pointer certificate, typed migration delta, existing mirrors, store heads, and
absence of external invocations match every frozen value, then appends its own activation intent bound
to that validated head. No journal publication can straddle the subsequent mirror/activation
transaction. That FULL transaction idempotently applies the newly validated lifecycle projection,
derives every anomaly-held null message/circuit deadline conservatively from the selected settlement,
then-current validated safe time, and retained relative evidence, and applies A-10.7's same normal-
outcome projection to every `upgrade_quiescing` row. It then deletes every logically expired selected
command row, verifies that the fixed journal's time-derived active projection excludes every
expired caller record, clears `deadline_derivation_pending`, records the activation watermark, and
clears holds before the lock is released and effects resume.

`upgrade.rollback` uses the same serialization and validates the complete authenticated lifecycle
projection/transcript before appending a rollback intent bound to its validated head. It never repoints to or modifies
the sealed source generation. Under A-14.3 it logically clones that source into a fresh generation,
creates a new branch epoch, applies every and only the validated lifecycle mirror, and verifies target
generation/transition IDs, transaction/comparison heads, and pointer certificate immediately before
activation. Its final clone transaction performs the same pending deadline derivation and clears the
marker, applies the same `upgrade_quiescing` outcome projection, and prunes the same logically expired
caller-key authority before clearing holds. No lifecycle or other journal record can appear between
projection validation and the clone pointer commit. It records rollback lineage and safe result evidence with the
fixed journal authoritative and activates only the new clone.

An unavailable, missing, or inconsistent checkpoint/tail projection, authenticated record outside the closed upgrade/lifecycle set,
unexpected selected-state row/head/certificate delta, or external invocation after quiescence appends a
lasting fixed-root `upgrade_diverged` resource record under the same gate. That record binds upgrade/source/target IDs,
expected and observed safe heads/digests, and the detecting phase; it contains no caller-key digest,
cannot expire with a command, and blocks ordinary activation, rollback, and deletion of every involved
generation at startup and before each operation. It is never an allowed SQLite delta and is never
silently discarded. A journal header, checkpoint, tail, HMAC, or sequence-integrity failure is a stronger
fixed-root corruption hold: because there is no authenticated head to extend, the service preserves the
bytes unchanged and appends neither poison nor resolution. A-10.7 forward repair is unavailable until
operator recovery restores one valid authenticated journal; it never overwrites integrity evidence.

`json.upgrade_activate.v1` is a closed request union. `mode = "activate"` follows the ordinary path.
`mode = "forward_repair"` additionally requires the exact unresolved `upgrade_diverged` record digest
and `acknowledge_preserve_current_state = true`. Under the same gates it may re-baseline only the
currently selected target after schema/integrity, pointer/epoch/comparison/tombstone, key-reference,
authorization-anchor, zero-invocation, and configuration checks all pass. One FULL transaction makes
rollback permanently ineligible and records a `repair_staged` baseline while every hold remains set.
The journal then appends an HMAC-bound resolution linked to the poison and repair-command digests. Only
a second FULL transaction that verifies that exact resolution may mark the divergence resolved, mirror
the command result, perform and clear any pending deadline derivation, apply the same
`upgrade_quiescing` outcome projection, prune logically expired caller-key authority, and clear holds.
A crash before the journal resolution remains staged/held; a crash
after it is finished idempotently by startup before effects. The poison provenance and resolution link
freeze `audit_supported_until` from the resolution's validated safe time using the configured 90-day
default/365-day maximum. They remain while any involved generation exists and throughout that half-open
audit horizon. After both dependencies end, only A-13.2's authenticated checkpoint fold may omit the
resolved pair; it never rewrites the pre-retirement image or treats an unresolved divergence as absent.
Corrupt or unverifiable state cannot be forward-repaired through this mode.
After activation/repair, an old binary must use a currently
compatible state; no snapshot rollback may erase accepted/effected work. Unknown-newer schema and
automatic downgrade always fail closed. Every state step is an operation in the frozen catalog; only
stopping/starting the listener and switching the immutable release symlink remain host lifecycle
actions. The release manifest states minimum/maximum schema.

## A-11. Fair scheduling, retry, and resource control

### A-11.1. Two-level round robin

The store persists a cursor over eligible provider IDs. Each claim starts after the last provider,
skips disabled/held/open-circuit/full-semaphore providers, and selects the next provider with due work.
Within that provider, a second persisted cursor selects the next principal with due work, then the
oldest `(next_attempt_at, created_sequence)` message for that pair.

After claim, both cursors commit with the lease. Runtime reserves one worker permit per enabled provider
plus a shared burst pool; global workers must be at least `enabled_provider_count + shared_burst`. A
hung provider can consume its own reserve and shared permits allowed by policy but never another
provider's reserved permit.

The published Sol reference profile is 8 AMD EPYC 9354P vCPUs, 31 GiB RAM, 8 GiB swap, and local ext4
on a non-rotational virtual device; the observed mount profile is
`rw,relatime,discard,errors=remount-ro,commit=30`. Each release evidence record captures free space and
verifies the exact SQLite profile from A-10.1. Under the named
fairness workload of at most 256 active principals per healthy provider, store-claim p99 must remain at
or below 10 ms and the oldest continuously due healthy pair must be considered within 3 seconds. The
validator rejects provider/worker/principal limits outside the measured envelope. Tests use multiple
hung/healthy fake providers and principals to prove the numeric bound, not merely eventual progress.

### A-11.2. Admission budgets

Budget counters are transactionally derived/maintained for:

- global queued message count and payload bytes;
- per-principal outstanding count/bytes and accepted request rate;
- per-provider outstanding count/bytes and accepted request rate;
- per-private-connector-identity outstanding count/bytes/rate so public aliases cannot bypass limits;
- API request concurrency and mailbox occupancy;
- configured filesystem emergency reserve (default 256 MiB or 10% of state volume, whichever is
  larger), DB/WAL growth, outcome/checkpoint allowance, backup staging+published+retained artifacts,
  restore upload+staging+current+rollback generations, bootstrap/configuration/state-key/migration
  staging generations, terminal and null-expiry operation-command evidence, worst-case
  restore-comparison batches/events through the 365-day support cap, backup-portable command-reservation
  key generations, fixed-root control-journal/recovery-ring reserve, and WAL/journal limits.

The fixed-root journal subreserve is at least
`2 * MAX_CONTROL_IMAGE_BYTES + MAX_CONTROL_RECORD_BYTES + 1 MiB` (17 MiB + 16 KiB with A-13.2's
first-slice constants): one maximum current image, one maximum replacement temp, one maximum encoded
record, and filesystem metadata slack. This physical subreserve is distinct from A-13.2's 2-MiB logical
reconciliation reserve and cannot be charged to ordinary resource admission.

Rate limiters use monotonic token buckets in process and initialize empty/conservative after restart;
they do not add write amplification through coarse checkpoint state. Hard depth/byte limits remain the
durable enforcement. Existing idempotency reads and reserved control operations do not consume new-
admission quota.

### A-11.3. Retry calculation

Retry configuration uses validated, closed domains. `factor_milli` is a fixed-point `u32` in thousandths
so that the backing factor is strictly greater than `1.0`; `factor_milli = 1_000` (constant backoff) is
rejected by configuration validation because it defeats PR-094 damping. Any value outside a domain fails
validation before readiness; there is no runtime coercion.

| Field | Type | Domain | Default |
|---|---|---|---|
| `base_delay_ms` | `u32` | `1_000 ..= 3_600_000` | `1_000` |
| `factor_milli` | `u32` fixed-point ×1000 | `1_001 ..= 16_000` (strictly > 1.0) | `2_000` |
| `max_delay_ms` | `u32` | `base_delay_ms ..= 3_600_000` | `900_000` |
| `max_attempts` | `u16` | `1 ..= 1_024` | `128` |
| `max_delivery_age_ms` | `u64` | `1_000 ..= 2_592_000_000` (30 d) | `86_400_000` |
| `multiplier_milli` | `u16` | `500 ..= 1_500` inclusive | injected |
| `ValidatedRetryAfter` | `DurationMillis` | `1_000 ..= 3_600_000` | absent |

The default policy is therefore maximum 128 attempts, 24-hour elapsed delivery age, base delay one
second, factor two, maximum 15 minutes, and deterministic multiplier in `[0.5, 1.5]`. Jitter is a
domain-separated MAC (`RetryJitterV1`) of message ID + attempt ordinal so the same scheduled delay
survives restart and tests can inject an oracle; its derived `multiplier_milli` is the only jitter output
core consumes. Configuration computes the earliest possible exhaustion window and rejects a policy whose
attempt cap would unintentionally dominate the declared age under normal backoff; an explicit
`allow_attempt_limited_delivery` acknowledgement is required for such a policy.

Version-one `JitterSource` is the source-side `MacProvider` HMAC-SHA-256 boundary. It accepts only
version `1`, the persisted purpose-09 `MacKeyRef`, a validated UUIDv7 MessageId, and ordinal
`1..=1023`; every other version or ordinal fails before a MAC call. For counter `c = 0..=255`, it
authenticates exactly
`"msgriver/retry-jitter/v1\0" || MacKeyId[40] || MessageId[16] || U16BE(n) || U8(c)` under the named
key and reads `x = U32BE(tag[0..4])`. It accepts only `x < 4_294_966_676` (`0xfffffd94`) and returns
`500 + (x mod 1001)`; a rejected candidate advances the counter, and exhaustion is a typed source
failure. The mapping from version one to this purpose/domain/framing is one-to-one; a future version
MUST NOT reuse it. Core receives only the `u16` result or typed failure, never a key, tag, counter, or
generic MAC capability. `JitterFactor(u32)` is the legacy standalone scaffold, not the source-port
contract; a later immutable port RED may supersede it, but no current persisted attempt uses its
32-byte seed input.

The version-one source contract freezes these independently reproducible HMAC-SHA-256 known answers.
`K1` is bytes `40..5f`; `K2` is bytes `60..7f`; `KeyId-7` is
`a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7000000000000002a0000000000000007`; `KeyId-8`
differs only in the final serial byte (`08`). Every MessageId below is UUIDv7 bytes. The final two rows
are one rejection sequence; no product-code generator may derive these expectations.

| key / key id | MessageId | ordinal / counter | HMAC-SHA-256 tag | result |
|---|---|---:|---|---:|
| `K1` / `KeyId-7` | `01900000000070008000000000000001` | `1 / 0` | `5093148a0eb5e7353acbb6859c9cb798fd71da15da914896bf6ce8c4f10d731f` | `1365` |
| `K1` / `KeyId-7` | `01900000000270008000000000000003` | `1023 / 0` | `d3880aebf1690b8b202a007d6ce80a4ed8799e6e7098341ecf57ef79ea108562` | `1405` |
| `K2` / `KeyId-8` | `01900000000370008000000000000004` | `2 / 0` | `6c246cda865baef045b8d070ebeb4f67b1a2d005e5cb619eba479c8fcd7959cb` | `1477` |
| `K1` / `KeyId-8` | `01900000000470008000000000000005` | `2 / 0` | `5c4490d2c25f99ea630b88a65ba58c14b26c89870fb33fd345f0344ce5d752f2` | `1444` |
| `K1` / `KeyId-7` | `01900000000070008000000002fd1a63` | `1 / 0` | `ffffff100c8540ac168988ff13a791471f00bfe0fa8a1cc1c0182f7dcd6a1db3` | rejected |
| `K1` / `KeyId-7` | `01900000000070008000000002fd1a63` | `1 / 1` | `2d122372a06ab9a8ff3eb7b3e96e81cc23e6a50f8a1c1705c487c72281fc0bc9` | `534` |

The recurrence is one-based and bounded. With `n` the completed attempt ordinal (`1 ..= max_attempts`),
exhaustion applies when `n >= max_attempts` and no retry is computed; otherwise `retry_index = n - 1` and:

```text
e_0     = min(base_delay_ms, max_delay_ms)
e_{k+1} = min(max_delay_ms, floor(u64(e_k) * u64(factor_milli) / 1_000))
          // saturating early exit: once e_k == max_delay_ms, all later terms equal it
exponential_ms   = e_{retry_index}
multiplier_milli = JitterSource.multiplier(derivation_version, jitter_key_id, message_id, n)
jittered_ms      = max(1, min(max_delay_ms,
                        floor(u128(exponential_ms) * u128(multiplier_milli) / 1_000)))
retry_ms         = max(jittered_ms, validated_retry_after_ms.unwrap_or(0))
```

Attempt-domain validation bounds the loop: `retry_index <= max_attempts − 1 <= 1_023`, so total work is at
most 1,023 checked multiplications; the local falsification's `factor=1, ordinal=1e9` case is rejected
twice over by `factor_milli >= 1_001` and `n <= 1_024`, and saturating early exit is an optimization, not
part of the bound. Rounding is floor at every step; all intermediates are widened (`u64` for the
recurrence, `u128` for the jitter product) and checked, and no step may wrap. With `base_delay_ms >=
1_000` and `multiplier_milli >= 500`, `jittered_ms >= 500`; the `max(1, …)` is the asserted nonzero floor
invariant that survives any future domain widening, and the domain lemma is proved separately so the floor
is never load-bearing in the first slice. Both caps apply: `max_delay_ms` is applied before and after
jitter, and `ValidatedRetryAfter`'s independent one-hour ceiling may raise `retry_ms` above `max_delay_ms`
but never above `3_600_000`. Known acceptance, committed cancellation, expiry/max-age, and attempt
exhaustion resolve before jitter is requested (PR-087, A-09.1). The durable wake boundary is
`min(checked(safe_now + retry_ms), expires_at, created_at + max_delivery_age_ms)`; at exact equality the
terminal guard is rechecked and no attempt begins.

The recurrence is frozen as five known answers over the default policy `base_delay_ms = 1_000`,
`factor_milli = 2_000`, `max_delay_ms = 900_000`, with the jitter `multiplier_milli` supplied as shown;
`Retry-After` is absent unless stated, and `final retry` is `max(jittered_ms,
validated_retry_after_ms.unwrap_or(0))`:

| base / factor / cap | completed `n` | multiplier | Retry-After | exponential | jittered | final retry |
|---|---:|---:|---:|---:|---:|---:|
| `1000 / 2000 / 900000` | 1 | 500 | absent | 1000 | 500 | 500 |
| `1000 / 2000 / 900000` | 2 | 1000 | absent | 2000 | 2000 | 2000 |
| `1000 / 2000 / 900000` | 10 | 1500 | absent | 512000 | 768000 | 768000 |
| `1000 / 2000 / 900000` | 11 | 1500 | absent | 900000 | 900000 | 900000 |
| `1000 / 2000 / 900000` | 1 | 500 | 3600000 | 1000 | 500 | 3600000 |

These literals are fixed before the executable model and are never regenerated as their own expectations.
Row `n = 10` saturates only after jitter; row `n = 11` is clamped to `max_delay_ms` before and after
jitter; the last row shows a one-hour `Retry-After` raising the final value above the backoff cap but
never above `3_600_000`.

Prepare persists the attempt ordinal, jitter derivation version, and `jitter_key_id` (`RetryJitterV1`
`MacKeyRef`) before dispatch; no attempt with a provider effect can lack this recoverable public reference.
Once derivation succeeds, its chosen `multiplier_milli`, relative delay, and `not_before` when safe UTC
exists are persisted exactly once and restart consumes those values without re-invoking the oracle. Under
`clock_anomaly` or `upgrade_quiescing`, the outcome transaction retains the stricter hold label. It may
persist a successful multiplier/relative delay (jitter needs no clock), leaving `next_attempt_at` and the
circuit `not_before` null; when the source is unavailable it instead retains null multiplier and relative
delay, and the selected hold-clear invokes the persisted-reference source before ordinary projection.
`JitterKeyDependency(ref)` means precisely a stored non-terminal message row whose highest-ordinal
stored attempt has persisted `RetryJitterV1` `jitter_key_id` equal to `ref`, regardless of whether its
`multiplier_milli` is null. This includes a prepared highest-ordinal attempt that never dispatched and
every retry-scheduled message whose completed highest-ordinal attempt already has a multiplier. Every `JitterKeyDependency(ref)` remains a
`RetryJitterV1` retirement and artifact-closure dependency under R3-INV-105/A-14.1.

If the source is unavailable after a retryable fenced provider outcome and no stricter clock/upgrade hold
is effective, that same outcome transaction retains its class and validated retry-after evidence in
`held(retry_jitter_unavailable)`, with null multiplier, relative/message/circuit deadlines, and lease. It
starts no new attempt. Recovery is invoked only by an observed purpose-09 repair/activation or a bounded
maintenance sweep, and only with validated safe time and no effective clock, upgrade, restore, or storage
hold; otherwise it leaves the row, its null deadlines, and its label unchanged. A permitted recovery
re-applies terminal precedence, derives through the persisted reference only, and projects once. An unavailable
result has no immediate self-wake. All-256-counter exhaustion is deterministic
for that persisted tuple, so repair/sweep leaves it held; only cancellation or expiry/max-age terminalizes
it. Cancellation and expiry/max-age are ordinary terminal maintenance for this hold; matching later
verifiable acknowledgement retains A-09.2 promotion.

The fallback sweep runs no more often than once per `60_000` milliseconds and examines at most `128`
`retry_jitter_unavailable` rows in one transaction batch. It walks the total `MessageId` order from a
durable circular cursor and advances that cursor atomically past every examined row, including an
unavailable result, before wrapping; therefore earlier unresolvable rows cannot starve a later row. It is
a bounded maintenance transition, not a new public operation or a scheduler wake: each retained unavailable
result leaves the row in place until the next bounded sweep, an observed key-ring event, cancellation, or expiry/max-age.

A valid delta-seconds or HTTP-date `Retry-After` is parsed at the provider/protocol boundary against
validated UTC, clamped to one second–one hour (a delta of zero clamps to one second; past or equal
HTTP-date, malformed input, and numeric/date overflow are ignored with a safe metric), and combined as
`max(backoff, retry_after)`. Core never sees raw header bytes and combines only by `max`. No retry begins
at or after message expiry/max age.

### A-11.4. Provider circuit

Each connector identity persists `closed`, `rate_limited`, or `open` plus `not_before`, failure class,
consecutive failures, and a one-probe lease. A `429` raises shared not-before. Authentication/config/TLS
failure opens the circuit and permits one exponentially spaced probe; queued messages do not each
probe. Success closes/reset; ambiguous/5xx outcomes contribute to bounded breaker policy without
erasing per-message retry evidence. Circuit changes wake the scheduler through a bounded notification.

While a connector's deadlines are deferred under `clock_anomaly`, `upgrade_quiescing`, or
`retry_jitter_unavailable`, multiple rate-
limited or auth-or-config outcomes may commit against one connector identity. The per-connector deferred
aggregate is a join-semilattice, so projection is independent of callback order and idempotent under
crash-retry:

```text
DeferredCircuit = {
  class:            max over the total order Transient < RateLimited < AuthOrConfig
  relative_hint_ms: max over retained bounded hints (0 when none)
}
merge(a, b) = { class: max(a.class, b.class),
                relative_hint_ms: max(a.relative_hint_ms, b.relative_hint_ms) }
```

`merge` is associative, commutative, and idempotent. No counter is accumulated into the aggregate:
`consecutive_failures` is derived at projection time by counting the held rows for that connector in
that transaction, so replaying an outcome cannot inflate it. The persisted multiplier and relative delay
of every deferred row (A-11.3) are the only inputs; at settlement the single shared circuit record
commits `not_before = safe_now + max(relative_hint_ms, policy_probe_backoff(class, consecutive_failures))`
exactly once per connector identity, in the same FULL transaction that derives every held message
deadline (A-10.7, A-11.5). A jitter-unavailable row contributes only retained aggregate evidence; no
probe or circuit deadline materializes until its successful persisted-reference projection. One shared
probe is published, never one per queued message (PR-085, PR-094).

### A-11.5. Clock and storage holds

Both modes run the clock guard and compare `(wall_delta - monotonic_delta)`. Absolute deviation over 30
seconds enters clock hold. Five consecutive samples over 60 seconds within 1 second propose automatic
settlement, but the hold leaves only after an event-triggered `clock.checkpoint` durably commits that
observation and any required selected-state mirror; an authorized local actor may instead explicitly
acknowledge the exact observation. The authenticated fixed-journal checkpoint
projection contains a nondecreasing `last_safe_wall_time` high-water, the last shutdown observation,
and current hold/observation; every journal publication advances those fields only under validated
time and fsyncs them with the file. In
both modes the coordinator also appends the internal `clock.checkpoint` lifecycle record at the
configured interval, which defaults to and may not exceed one hour, on automatic-settlement state
change, and on clean shutdown, under the same owner lock and atomic file/parent barriers, so a long quiet
runtime cannot leave only a stale fixed-root baseline. This autonomous record has no API/CLI descriptor,
advances the authenticated safe-time checkpoint authority only for a clock-guard-accepted observation, records whether
its closed reason is `periodic`, `automatic_settlement`, `clean_shutdown`, or `expiry_proof` plus any
named hold generation, and is mirrored into selected SQLite when one exists. This authority exists
before bootstrap. Its genesis is an explicit control-journal initialization decision: the initializer
MUST first obtain a clock-guard-accepted baseline observation. Before the complete authenticated
genesis image commits, no fixed-root `ClockAuthority` exists; that state is initialization-unavailable,
not a clock hold, and cannot authorize bootstrap, readiness, expiry, or an effect. The genesis
checkpoint projection then sets `last_safe_wall_time` exactly to that observation's wall time, has a
clear current hold, and has an explicit absent last-shutdown observation (never an epoch, zero, or
synthesized shutdown result). It covers the genesis head `(0, [0; 32])` with an empty tail. This
projection is not a `clock.checkpoint` tail envelope and therefore does not invent a prior/new body
transition or a process instance; the first tail lifecycle record uses the ordinary authenticated
marker as its `prior_safe_time`. This decision supplies only the clock-authority facts of a future
complete image. It does not make a partial image valid: every other A-13.2 projection authority and
the canonical image framing remain required before any image may be published. Neither copy can
override a newer/stricter hold from the other. The effective
comparison high-water is the maximum of the authenticated fixed-root and selected-SQLite markers that
exist; a lagging committed copy is reconciled forward and never lowers the leading copy. Selected
SQLite and fixed-root high-waters never decrease. Startup performs that reconciliation before result/
reservation lookup or readiness.

The clock portion of a checkpoint is the private canonical `clock-authority/v1`
subcodec. This is an explicit framing decision for that one projection value,
not an image codec or a lifecycle transition. It is exactly `V || S || H ||
[G || D]? || Q || [W]?`, where `V` is `U8(1)`, `S` is the signed-big-endian
`I64` safe-time marker, `H` and `Q` are closed `U8` presence tags, `G` is a
nonzero `U64BE` hold generation, `D` is its nonzero 32-byte observation digest,
and `W` is the signed-big-endian `I64` accepted wall-time of the last clean
shutdown observation. `H=0` has no `G || D`; `H=1` requires both. `Q=0` has no
`W`; `Q=1` requires it. Thus only lengths 11, 19, 51, and 59 are canonical,
with hold before shutdown. A genesis value is exactly the clear/absent 11-byte
form described above. A clean-shutdown checkpoint may replace `W` only with
its clock-guard-accepted observation; shutdown under hold preserves `W` and
records its process truth only through `system.shutdown` addressed-state cells.
The decoder first requires 11 bytes before it reads `V`, `H`, or the first
possible `Q`. If `H=1`, it requires 51 bytes before reading `Q` at byte 50;
otherwise it reads `Q` at byte 10. It then requires the one exact canonical
length selected by those tags before any optional slice, validates version and
tag/layout, then validates the nonzero hold address. The containing checkpoint
authenticates the bytes before exposing this value.
It neither applies tail records nor clears a hold: the separately typed
lifecycle automata own those transitions and recovery. Checkpoint generation,
image framing, checkpoint membership, tail replay, and the cell codecs remain
outside this subcodec. Before a request response first
depends on an accepted observation crossing a retained idempotency, generic-command, or fixed-root-
reservation boundary above its effective durable high-water, the coordinator persists that
observation through an immediate `clock.checkpoint` and required mirror (or the ordinary same-store
delete/fresh-intent transaction advances it atomically). During A-10.7 this checkpoint is an allowed
lifecycle record. Failure to make the proof durable returns unavailable without stale disclosure or a
fresh effect.

Startup in either mode compares current wall time with that fixed-root marker and every retained journal
timestamp. Normal mode additionally compares SQLite's marker. Negative offset beyond 30 seconds,
forward elapsed time beyond the configured plausible-downtime ceiling (default seven days), marker
divergence, or invalid ordering enters the same fixed-root-persisted `clock_anomaly` hold. The service
rejects configuration unless that ceiling is strictly greater than checkpoint interval plus the
30-second anomaly threshold plus the 60-second settle window.
The service still serves authenticated health/readiness plus `clock.show` and `clock.acknowledge` on its active UDS.
`clock.show` exposes the opaque current hold generation and observation digest required by an exact
acknowledgement; it exposes no raw clock sample or credential. The held service
performs no fresh business admission/effect, expiry, max-age, retry, idempotency/command cleanup,
journal cleanup, or deadline transition. Existing authenticated idempotency/command lookup and committed-
result retrieval remain available only for null-expiry rows or boundaries still above the effective
high-water; anomalous wall appearance alone cannot release them. A boundary at or below that high-water
is proven-expired and stays absent even when bytes remain: no result, conflict, namespace marker,
portable reservation, or MAC dependency can revive. A proven-expired same key, a miss/never-seen key,
and an expiry-bearing submission are fresh-effect attempts and return the stricter restore/upgrade hold
or exactly `503 clock_hold` with null `retry_after_ms`, never stale authority.

Combined-hold precedence is total. After authentication/authorization, generation-guarded exact-
receipt recovery, complete-expected-current same-value no-op, or complete-address conflict resolves effect-free before
hold disclosure. First for every remaining fresh mutation, an existing restore/upgrade hold rejects
every operation that is not explicitly permitted through that hold, so an otherwise-forbidden backup,
prepare, drain, or ordinary mutator reports the pre-existing hold without disclosing a lower-priority conflict.
`upgrade_prepare_in_progress` during the nonterminal pre-watermark coordinator is such an upgrade hold
and wins over `clock_hold`, just like `upgrade_activation_pending`. Second, a
cataloged activation, rollback, forward-repair, or restore-resume transition that is explicitly
permitted through its own hold returns exact `503 clock_hold` with null `retry_after_ms` only when safe-
time proof or deadline derivation is its immediate blocker; that original hold remains set. Required
nonmutating branch-serial validation may still precede clock evaluation and return
`state_incarnation_unavailable` without disclosing or changing a hold. Third, with no pre-existing
restore/upgrade hold and usable allocator state, every cataloged fresh mutator—including a different-
value complete-expected-current `admission.set`, `backup.create`, `backup.cancel`, `upgrade.prepare`,
and `drain.start`—returns that same `clock_hold` before control-capacity admission, coordinator creation,
or reporting an admission, drain, or coordinator conflict. No control reserve changes this order.

Clock-held mutations are limited to the event-triggered automatic-settlement checkpoint or exact-
observation `clock.acknowledge`, which may settle the two clock authorities; graceful-shutdown lifecycle intent/result, which may record process truth without
advancing safe-time fields; authenticated message cancellation, which may terminalize queued/held/retry work or
set `cancel_requested` on delivering work; and the fenced outcome of a provider invocation already
dispatched before the hold. A backup cancellation intent durably committed before the clock anomaly may
finish only its no-effect owned-file cleanup, parent-directory fsync, terminal transaction, and pin
release under retained deadline proof. A new `backup.cancel` received during the hold is not that
authority: it returns exact `503 clock_hold` with null `retry_after_ms` and changes no job, file, pin, or
deadline state. Otherwise a backup coordinator admitted before the hold may perform only crash-safe
inspection, reconciliation, and owned-staging cleanup that cannot copy a new page, create or rename a
published artifact, or claim `complete`. No other path may perform cleanup, expiry, retry, lease release, or a new provider
invocation, and any stricter restore/upgrade hold remains conjunctive. The in-flight invocation may
return so its truth is not lost. Known acceptance commits normally under A-09.1's acceptance-first
precedence; a permanent outcome commits under that fence subject to cancellation/expiry precedence.
Transient, rate-limited, authentication/configuration, or
ambiguous results commit attempt evidence and sticky uncertainty as applicable, put the message in
`clock_anomaly` hold with null `next_attempt_at`, and cannot schedule or start another attempt until
settlement derives a conservative deadline from validated safe time. A bounded relative provider hint
may be retained as evidence, but no circuit `not_before` is materialized; settlement first invokes the
persisted-reference jitter derivation, changing an unavailable/exhausted source to
`retry_jitter_unavailable` with null deadlines and retained deferred evidence, and derives both circuit
and message deadlines conservatively from then-current validated safe time only on success. A concurrent cancellation follows
A-09.1 precedence and is resolved before any post-settlement attempt. The exact acknowledgement is a fixed-root addressed-state operation available to the state-owner peer before SQLite exists. Its request supplies the current nonzero hold generation, exact observation digest, and explicit risk acknowledgement. A-13.2.4 governs phase/result recovery, obligation retention, and address-scoped disclosure: exact current repetition or eligible completed repetition is effect-free; every other address returns state_address_conflict. Acknowledge phase 1 to 2 raises fixed-root safe time without clearing the hold. With no selected state, tag-0 phase-3 publication is settlement-effective; with selected state, tag-1 mirror commit completes through the required FULL mirror barrier. Outside A-10.7's rollback-eligible phase, that selected transaction invokes persisted-reference jitter derivation for every anomaly-held null message/circuit deadline: unavailable/exhausted source changes that row to `retry_jitter_unavailable` with null deadlines and retained deferred evidence, while successful derivation materializes its deadline. It then clears the selected clock hold atomically. Every crash prefix before the required barrier retains the hold and starts no attempt; startup completes the exact mirror idempotently from authenticated truth or leaves the hold set.

Every publication clearing a named hold, including automatic settlement, atomically finalizes its pending acknowledgement obligations under A-13.2.4. Completion reads pre-publication clock authority: retain only for the exact named hold, otherwise drop when authority is greater or absent, and never clear a newer hold. A newer durable hold evicts older completed acknowledgement eligibility. Consequently H1 cannot become retryable again after H2 becomes durable, including after H2 clears or the journal folds.

During A-10.7's rollback-
eligible phase, however, its selected-state mirror contains only the fixed-root observation/authority
and `deadline_derivation_pending`. Automatic settlement follows the identical rule through its
event-triggered checkpoint mirror. Both retain relative message/circuit evidence without materializing
any scheduler-visible deadline. Activation, rollback-clone selection, or the final forward-repair
hold-clear transaction scans every `clock_anomaly` row with a null message/circuit deadline and invokes
its persisted-reference jitter derivation: unavailable/exhausted source changes the row to
`retry_jitter_unavailable` with null deadlines and retained deferred evidence, while successful derivation
uses then-current validated safe time, applies the retained deferred outcome class including a single shared
circuit probe for authentication/configuration, clears the marker, and only then resumes effects. The service
does not crash-loop or silently trust service-manager time ordering.

Disk budget is sampled before admission and periodically through a Linux platform adapter. It accounts
separately for state and optional backup volumes and the full simultaneous peak described in A-11.2.
Below reserve, admission stops; if remaining headroom cannot cover bounded outcome writes, new
dispatches pause. Read/status/cancel/purge/backup-abort retain reserved channel slots. Filesystem probe
failure is fail-loud for new admission, not “unlimited.”

### A-11.6. Admission and drain state

`admission.show` and generation-guarded `admission.set` expose a durable operator state of `open` or
`closed` with its 32-byte `resource_incarnation`, nonzero checked `u64` generation, actor, reason code,
changed time, and one fixed nullable incarnation-bound last-transition receipt. It survives restart and
is distinct from safety, restore, upgrade, and shutdown holds. Opening operator admission cannot
override another hold.
Upgrade activation and forward repair preserve the exact operator row while clearing only their safety
holds. Restore and rollback are the sole branch transitions that replace its address. A-14.3 writes a
new restore-closed row under the allocated history epoch/incarnation before selection, and A-14.4 resume
does not open it. Bootstrap, every restore, and every rollback clone initialize the selected admission
address at generation one with a null receipt; rollback preserves the chosen source's operator value,
actor, reason, and changed time rather than a discarded descendant value.
`admission.set` also serializes against A-10.7's prepare coordinator. Before the first quiescing
transaction a different desired value commits normally and is captured by that transaction. After
authentication/authorization, exact still-current incarnation-bound receipt recovery and a complete-
expected-current value already equal to the complete desired state return the existing tuple as effect-
free no-ops before every safety/clock/coordinator conflict check in every phase. Any other incarnation/
generation mismatch returns `state_generation_conflict`. Only a complete-expected-current different
value is a fresh mutator; it increments generation and replaces the receipt in the same FULL
transaction. While the coordinator is nonterminal
that fresh mutation returns `409 upgrade_prepare_in_progress`; after failure it operates on restored terminal truth,
while after a successful watermark it remains frozen under
`upgrade_activation_pending`. Thus `prepare_failed` can restore only an unchanged snapshot and can
never overwrite a later operator close.

After effect-free same-key command-result lookup, a fresh `drain.start` first checks that admission can
advance. In one FULL transaction it always increments the admission generation, sets operator admission
closed, clears the guarded admission receipt, and records the generated drain ID, purpose-separated
keyed command digest/version, deadline, and running status—even if operator admission was already
closed. At `u64::MAX`, it returns `state_generation_exhausted` before a command row, coordinator, audit,
or admission change. It returns the accepted `running` result within the ordinary handler deadline. A
durable drain coordinator—not the request handler or store actor—then observes eligible accepted work
and in-flight leases through reserved control capacity. The API and CLI poll by retrying the same
command key, which returns the same running or terminal record without another state transition.
Connection loss never cancels the coordinator, and restart resumes it. A different key while one drain
is active receives a safe `drain_in_progress` result rather than creating a second coordinator or
advancing admission again.

The terminal result is either `complete` with zero actionable remainder or `timed_out` with safe
bounded counts; it never silently reopens. Existing idempotency hits remain available in both outcomes.
The store actor's `complete` zero-remainder and `timed_out` bounded-remainder terminal transactions both
serialize against enqueue and A-10.6 replay. Admission was already closed by `drain.start`; both
insertion paths recheck it, so neither terminal outcome can have a child appear behind it.
`admission.show` includes the safe current or most recent drain ID, original deadline, phase, and
bounded counts, never its command key, so terminal truth does not depend on retaining the initiating
shell. An explicit `admission.set open` is the only operator reversal. Process shutdown may stop
listener acceptance ephemerally but does not overwrite the persisted operator choice. Prepare, backup,
restore, clock, storage, and shutdown safety closures likewise use separate holds; only the explicitly
listed admission writers or branch replacement change the operator row.

## A-12. Connector boundary and ntfy v1

### A-12.1. Driver contract

The connector crate exposes a closed `Driver` enum dispatched by exhaustive match; no dynamic plugin or
`dyn async` trait object is needed in the first slice. Each variant implements:

```text
validate_and_canonicalize(registration, destination, content, options) -> CanonicalDelivery
catalog_contract(registration) -> SafeProviderContract
deliver(attempt_context, canonical_delivery, secret_snapshot) -> DeliveryOutcome
```

`DeliveryOutcome` is a closed enum: `Accepted { safe_provider_id? }`, `Transient`, `RateLimited`,
`Permanent`, `AuthOrConfig`, or `Ambiguous`. It contains only bounded safe error codes and retry hints;
raw responses are consumed/redacted inside the driver. Drivers never receive the store, principal API
key, logger field builder, or arbitrary URL.

The deterministic fake driver lives behind test-only construction and records typed calls in memory.
The loopback ntfy fake is a real HTTP peer used for byte-level conformance; neither is a user-visible
provider kind.

### A-12.2. HTTP client profile

One low-level Hyper HTTP/1 + Rustls connection policy is built per connector identity. Each delivery
attempt constructs and sends exactly one request; the stack has no automatic retry, redirect, proxy,
cookie, decompression, or HTTP/2 behavior. It enforces:

- redirects rejected as a typed outcome and never followed;
- environment/system proxy use absent; a future explicit proxy is a separately reviewed transport;
- verified WebPKI or operator-provided CA roots, hostname verification, and no insecure mode;
- connect timeout 2 seconds, total timeout from validated provider config (default 5 seconds);
- `http1::Builder::max_headers`, `max_buf_size`, request/response line/header limits of 16 KiB/64
  headers, response body limit 16 KiB, and `Content-Encoding` identity-only;
- one request per connection/attempt in v1, avoiding hidden pool replay and ambiguous reuse;
- `User-Agent: msgriver/<version>` and no caller-controlled headers.

Plain HTTP construction succeeds only for literal `127.0.0.0/8` or `::1`, with no credential or proxy.
TLS permits versions 1.2 and 1.3 only. TLS validation failures are `AuthOrConfig`, never a tight
transient retry.

### A-12.3. ntfy request mapping

The first-slice native request is:

```text
POST <canonical-base-path>/<validated-topic>
Content-Type: text/plain; charset=utf-8
X-Title: <validated raw UTF-8 title>                    # only when present
X-Priority: min|low|default|high|max                  # only when non-default
X-Tags: comma-separated validated ASCII tags          # only when non-empty
Authorization: Bearer <operator token>                # only when configured over HTTPS

<exact non-empty UTF-8 text bytes, at most 4096 bytes on the default ntfy profile>
```

Title validation rejects every decoded Unicode scalar in `U+0000..=U+001F` or
`U+007F..=U+009F` before header construction; this includes CR, LF, and NUL.
The body follows PR-062's narrower C0/C1 policy, preserving HT, LF, and CR as
exact text bytes. Hyper receives a validated header value rather than
concatenated raw bytes.

The URL library appends exactly one path segment to the canonical base path; the validated topic
already excludes escaping characters. Click, attach, actions, email forwarding, scheduling, sequence
updates, templates, Markdown flags, arbitrary JSON, query parameters, and custom headers are absent.

Only HTTP `200` with a bounded valid ntfy JSON object containing a grammar-valid `id` is known
acceptance. The ID may be retained as safe attempt evidence. A `200` with missing/invalid/truncated body
is ambiguous because the external effect may exist.

Outcome classification:

| Observation | Outcome |
|---|---|
| DNS/connect failure before request bytes | `Transient` |
| TLS/trust/auth setup failure | `AuthOrConfig` |
| write failure after dispatch may begin; timeout/drop while awaiting response | `Ambiguous` |
| `200` + valid bounded acknowledgement JSON | `Accepted` |
| `400`, `413`, `422` | `Permanent` |
| `401`, `403`, `404` | `AuthOrConfig` |
| `429` | `RateLimited` with bounded `Retry-After` |
| other `4xx` | `Permanent` unless a future documented ntfy contract says otherwise |
| `5xx` | `Ambiguous` under product default |
| redirect | `AuthOrConfig`; never followed |

The contract test asserts exact method, canonical URL, headers, UTF-8 body, absence of prohibited
headers, response bounds, classification, and no second-listener disclosure. Because upstream ntfy
defaults to converting bodies above 4096 bytes into attachments and substitutes `triggered` for an
empty body, the native first-slice profile rejects empty text and enforces
`effective_text_bytes = min(4096, operator_limit)`. An operator may lower that limit but cannot raise it;
a compatible server above 4096 requires a later versioned release change. Sol uses credentialless
`http://127.0.0.1:8090`. Hermetic and live proofs include a non-ASCII title, exact 4096-byte body,
priority/tags, and returned acknowledgement ID.

## A-13. Configuration, secrets, and runtime modes

### A-13.1. Configuration snapshot

`/etc/msgriver/bootstrap.toml` is a minimal host envelope: state root, expected service identity,
systemd credential root, pre-opened socket names, and compiled resource ceiling profile. Every product
setting—provider registrations/endpoints/reference names, delivery/admission/retry/retention policy,
listener enablement, quotas, storage budgets, and telemetry policy—lives in a canonical versioned
operational configuration stored under the active state. Principals, grants, peer mappings, and API
keys remain independently versioned state through their own operations. Every object denies unknown
fields.

#### A-13.1.1. Release bootstrap envelope v1

The only release bootstrap source is the root-controlled TOML file
`/etc/msgriver/bootstrap.toml`. It has no tables and exactly these six
top-level keys, with no unknown or duplicate key accepted:

```toml
version = 1
state_root = "/srv/msgriver/data"
service_user = "msgriver"
credential_root = "/run/credentials/msgriver"
socket_names = []
resource_ceiling_profile = "baseline-v1"
```

`version` is integer `1`. The other scalars are UTF-8 TOML strings;
`socket_names` is exactly the empty TOML string array in v1. `state_root` and
`credential_root` must match the displayed absolute spelling exactly: no
relative path, dot component, trailing slash, NUL or alternate spelling is
accepted. `service_user` is exactly the closed literal `msgriver`; it never
resolves through NSS, passwd, nscd, sssd or a supplementary-group lookup. The
existing non-root validation owns the effective UID check. `baseline-v1` is the
sole compiled resource-ceiling profile and means the existing no-core/
non-dumpable process policy. A later ADR must define every listener socket name
and compiled profile before either field can broaden.

The parent `/etc/msgriver` is a real directory owned by the compiled expected
UID and the effective GID, mode `0750`. The envelope is a single-link regular
file owned by that same pair, mode `0640`, no larger than 4096 bytes. Startup
validates parent/file metadata, opens no-follow, and requires before/open/after
device, inode and metadata identity to agree. Missing, symlinked, hard-linked,
nonregular, wrong-owner, wrong-group, broader-mode, oversized, malformed,
incomplete, duplicate, unknown or replaced input fails closed before owner-lock
acquisition.

The envelope contains neither a secret/secret-reference name nor operational
configuration. In v1 `credential_root` is structural metadata only and is not
opened; the empty socket set grants no socket authority. The binary accepts no
environment, CLI, current-directory, search-path, include, interpolation or
alternate bootstrap source. After process policy and non-root validation, a
valid envelope may supply only the fixed root to the existing trusted-root and
owner-lock primitives; execution remains unavailable at `SelectedState`.
It does not select/open state, read credentials, bind/listen, select
operational configuration, start a worker, or enable provider/ntfy authority.
All failures retain the fixed redacted non-ready diagnostic.

Parsing produces immutable `ValidatedConfig` values containing only closed enums, validated newtypes,
and bounded collections. Validation covers all registrations together, compiled driver support,
outstanding connector identities, names in one atomically read `SecretReferenceCatalog` generation,
URL canonicalization, worker/fairness/retry/storage bounds, and computes SHA-256 over canonical
non-secret bytes. It records the catalog generation/digest in the compatibility report but never
accepts provider secret values. Canonical serialized bytes are capped at 49,152; codec framing and
activation metadata must keep the complete request below the ordinary 65,536-byte command-body ceiling.
No partially valid or oversized snapshot reaches a listener or worker.

`configuration.validate` receives the complete candidate plus expected config generation, transaction
sequence, and authorization epoch. It returns a compatibility report and digest; there is no validation
ticket. The canonical operational document exists only as bytes and metadata in the staged SQLite
`configuration_generations` rows; there is no second operational-config file inside a state generation.

With normal mode stopped, `configuration.activate` acquires the maintenance generation-transition
gate, atomically reads the metadata-only secret-reference catalog, repeats full validation against
current state, and uses the copy-on-generation protocol in A-14.3. The catalog generation/digest is
reopened through the fixed metadata-directory descriptor and rechecked immediately before pointer
commit; an inode/generation/digest change aborts the staging generation instead of
activating evidence validated against another name set. In the staged database, one `synchronous=FULL`
transaction records the candidate bytes, digest, reference-catalog generation/digest, new configuration
generation, actor, command result, and selected configuration row. The staged state is then checkpointed,
closed, and durably finalized. Atomic replacement of the fixed-root
`active-state` file—not the inner SQLite transaction—is the sole externally committed activation
point. The maintenance process reopens and verifies the newly selected generation before returning the
committed response. Crash therefore yields exactly the prior state generation or the complete new one.
Normal startup always parses and fully revalidates the active bytes before listeners/workers. Invalid,
stale, or concurrently superseded candidates leave the prior generation active. There is no live
reload or in-place configuration activation.

`configuration.show` returns the complete active non-secret operational document and generation only
over local UDS/state-owner authorization. It includes endpoints, connector identities, policy, and
secret *reference names* needed for reproducible export, but no secret values, host credential paths,
state-key bytes, or bootstrap envelope. This is the only supported export; neither CLI nor deployment
tooling reads hidden operational files.

### A-13.2. Secret and key material

Configuration stores references, never provider secrets. A reference selects one protected regular
file or systemd credential. Environment secret values are rejected in v1. File reads use no-follow/open-first
checks, require an expected owner and no group/other write bits, enforce a small byte cap, and strip no
content silently.

The service state key ring is separate from provider credentials and contains the closed
`MacPurpose`-separated MAC keys of A-04.2: API-key verification; idempotency, replay, and command
lookup/fingerprint MACs; deterministic retry jitter; artifact internal authentication; and portable
fixed-command reservation authentication (`PortableReservationV1`). Every key is identified and resolved
by its `MacKeyRef` (A-04.1), not by a bare counter, and every `MacPurpose`, including
`PortableReservationV1`, owns an independent ring slice. The retained bound applies to every such slice:
`MAX_RETAINED_MAC_KEYS_PER_PURPOSE = 16` (one active plus at most fifteen retained), so lookup performs at
most sixteen HMAC-SHA-256 evaluations per purpose per submit pre-pass—bounded work under INV-009,
independent of rotation history. It is stored
owner-only within each complete state generation. A
separately escrowed recovery-key ring lives under the fixed owner root, is never inside a state
generation or `.mrb`, and encrypts backup state-key sections.

The authenticated state-generation header carries the selected `OriginIncarnation` plus one authenticated
`mac_serial_high_water` two-limb pair for every closed `MacPurpose`; a newly selected origin starts every
value at zero. MAC key lifecycle obeys a total precedence and a set of closed invariants. R3-INV-101 — An
existing `MacKeyRef` MUST remain immutable, and a transition MUST NOT renumber, reissue, re-purpose, or
re-origin an existing key. R3-INV-102 — Allocation MUST use checked
`next = checked_add(selected_origin_high_water[purpose], 1)`; a successful publication MUST store `next`
as both the new key serial and new high-water, and retirement MUST NOT decrement high-water or permit
reuse after deleting the greatest retained serial. R3-INV-103 — `state_key.rotate` MUST allocate under
the currently selected `ResourceIncarnation`; a branch-allocating restore/rollback MUST select a fresh
origin whose purpose high-waters start at zero, while continuations MUST preserve the vector except that
a successful `state_key.rotate` advances exactly its selected purpose. R3-INV-104 — Bootstrap MUST
create initial internal keys under its allocated incarnation, and the pre-bootstrap portable key MUST
keep `PreBootstrapOrigin` unchanged when copied into the first selected state. R3-INV-105 — Retirement
MUST be rejected while any live or retained idempotency, replay, or command row; any
`JitterKeyDependency(ref)` as defined exactly in A-11.3; any retained or suspended `api_keys` row; or any
unexpired artifact or provenance closure names the key. This retry-jitter dependency is exactly the A-14.1
closure set: a referenced key pins one of the fixed sixteen purpose-local slots, so rotation may return
`409 mac_key_ring_full` until cancellation, expiry/max-age, or other dependency termination makes
retirement admissible. Retirement MUST be the only way to free a ring slot.
R3-INV-106 — Rotation MUST evaluate, in order, selected-origin and high-water integrity, serial
exhaustion, then retained-ring capacity, and only then checked allocation and entropy; ring overflow MUST
return stable `409 mac_key_ring_full` before entropy draw, key file, journal intent, high-water, or ring
mutation, so the operator retires a dependency-free generation or waits for the covering window.
R3-INV-107 — Serial exhaustion at `u64::MAX` for one `(origin, purpose)` MUST return
`503 mac_key_serial_exhausted` before any effect and MUST degrade readiness with reason
`mac_key_serial_exhausted`; it MUST remain recoverable without data loss by a supported branch transition
that allocates a fresh origin whose serial restarts at 1, and unlike `incarnation_exhausted` it MUST NOT
be terminal for the owner root. R3-INV-108 — Two ring entries with equal `MacKeyRef` and unequal key
bytes MUST be treated as corruption and MUST return `409 mac_key_identity_conflict`, failing closed before
destination key-file staging, generation finalization, pointer selection, or any selected-state mutation.
On restore, the durable command/input intent and any applicable same-intent branch-serial burn MUST be
treated as recoverable pre-comparison state because candidate rows cannot be authenticated and compared
before artifact decryption; equal `MacKeyId` values under different purposes MUST remain valid and resolve
to distinct purpose-qualified paths. R3-INV-109 — A `MacKeyId`
whose `OriginIncarnation` is foreign through an authenticated blank-restore boundary MUST be classified
as an `imported_key_origin`; it MUST NOT be a local allocator witness under allocator rules 18–19,
MUST NOT contribute selected-origin purpose-local high-water evidence, and MUST NOT trigger a fixed-root
corruption hold. R3-INV-110 — The host-local journal-integrity key MUST remain outside this ring
because it is the root of trust that derives `OwnerNamespace`; the implementation MUST NOT assign it a
`MacKeyId` because that would be circular, and its format version MUST remain governed by A-10.7's plan
binding. R3-INV-111 — The
selected origin, complete purpose-local high-water vector, new ring row, and active-key pointer MUST form
one authenticated publication; the purpose-qualified key file MUST be durable first, so a crash before
publication leaves at most an unreferenced file for bounded cleanup while a published generation MUST
NOT expose the row without its advanced high-water. R3-INV-112 — Load and artifact verification MUST
require every retained key under the selected origin to have `serial <= high_water[purpose]` and every
high-water to appear exactly once with valid limbs; a missing, lower, duplicate-purpose, or
foreign-origin-derived allocator value MUST be corruption before selection.

Maintenance API/CLI provides state-key list/rotate/retire and recovery-key list/generate/import/retire.
Bootstrap creates the initial internal service-state keys required by its new database, but
creates no recovery key or API key and exports no secret; its response is secret-free. Later state-key
rotation/retirement uses the same copy-on-generation and sole pointer-commit protocol as configuration
activation and never mutates a selected ring in place. The staged database and staged key files agree
before the generation is finalized. Retirement MUST apply exactly the dependency gate in R3-INV-105.
An inactive generation
remains sealed and may still contain the logically
retired key until explicit state-generation cleanup.

For the recovery ring, at most one generation is `active` and backup-selectable; zero is valid before
initial escrow or after explicit retirement and makes backup creation unavailable. Generating and
escrow-activating a successor is the complete rotation: acknowledgement atomically marks the successor
active and demotes the predecessor to retained/non-selectable. Importing and activating an already
escrowed successor performs the same demotion. Retained predecessors remain available to decrypt
artifacts that name them until explicit dependency-checked retirement; no uncataloged
`recovery_key.rotate` action exists.

The fixed owner root contains one bounded, authenticated control journal that is usable without SQLite.
Initialization obtains five independent exact 32-byte samples from the fallible operating-system CSPRNG
before publishing any key. An entropy error, short sample, all-zero sample, or any two equal samples
fails closed with no usable key, journal intent, branch serial, state generation, or active pointer.
Only validated samples become five purpose-separated mode-`0600` keys through independent
temp-`O_EXCL` → file-fsync → rename → parent-fsync barriers: a host-local journal-integrity/key-digest
key that is never exported, a portable command-reservation MAC generation that may enter only the
recovery-key-encrypted artifact state section, and three pre-bootstrap command-tag MAC generations for
fixed-root purposes `06`, `07`, and `08`. No intent may exist before all five final keys, and
incomplete temps are inert/reclaimable. The local key authenticates the journal and protects its local
caller-key digests; the portable key cannot authenticate journal bytes or authorize result disclosure.
The same local key authenticates the journal header's recomputed owner namespace and branch-serial
high-water. The three command-tag keys share one reserved nonzero pre-bootstrap identity that is never
`PreBootstrapOrigin` (it stays exclusive to the portable-reservation key), never a zero key, and never
a reused purpose; each holds serial one and is immutable and purpose-qualified. They are never
allocator witnesses and are never re-keyed; bootstrap copies them into the first selected state as
retained verification entries, so purposes `06`/`07`/`08` carry defined, separately verifiable tag
authority before bootstrap while the operation-`07`/`08` profiles remain separately versioned
decisions. The separately HMAC-bound checkpoint owns fixed-root safe-time/clock-hold authority and
every active-state generation/history-epoch pointer certificate.

The complete journal image has three authenticated regions: one header, one canonical state checkpoint,
and one ordered tail. First-slice constants are `MAX_CONTROL_IMAGE_BYTES = 8 MiB`,
`MAX_CONTROL_HEADER_BYTES = 16 KiB`,
`MAX_CONTROL_CHECKPOINT_BYTES = 6 MiB - MAX_CONTROL_HEADER_BYTES`,
`MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES = 4 MiB - MAX_CONTROL_HEADER_BYTES`,
`MAX_CONTROL_RECONCILIATION_CHECKPOINT_BYTES = 2 MiB`,
`MAX_CONTROL_CHECKPOINT_ENTRIES = 4,096`, `MAX_CONTROL_TAIL_BYTES = 2 MiB`,
`MAX_CONTROL_TAIL_RECORDS = 128`, and `MAX_CONTROL_RECORD_BYTES = 16 KiB`, all including their own
framing. `16 KiB + (4 MiB - 16 KiB) + 2 MiB + 2 MiB = 8 MiB` exactly partitions header, ordinary
checkpoint projection, reconciliation checkpoint projection, and tail. Ordinary admission may occupy at most the
`MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES` region and 4,032 projected entries.
`MAX_CONTROL_RECONCILIATION_ENTRIES = 60` plus `MAX_CONTROL_ADDRESSED_STATE_CELLS = 4` exactly partition
the remaining 2-MiB/64-entry checkpoint reserve; the independent 2-MiB tail remains available for
publication/folding records. The four cells are current/last for each of the two addressed-state
operations and replace in place.
Every fixed-root
protocol has an independently frozen maximum of at most 64 continuation records. After first folding
an ordinary tail, that worst case plus one clock-or-shutdown publication and one terminal publication
uses at most 66 tail records and 1,056 KiB, leaving both the 128-record tail cap and 2-MiB reserve
strictly open; its non-addressed reconciliation projection uses at most 60 entries. Validation rejects arithmetic
overflow, a count/length over any cap, trailing bytes, or a noncanonical ordering before allocating from
an encoded length.

The HMAC-bound header carries the immutable derived owner namespace and the nondecreasing branch-serial
high-water in addition to format/key versions and framing lengths. Startup recomputes and constant-time
compares the namespace, validates a canonical nonnegative high-water, and reconciles an allocating
intent only when its serial is exactly at or below that authenticated high-water and its target bytes
match the derivation. Missing, rolled-back, mismatched, or unauthenticated allocator fields fail before
SQLite or pointer selection; neither a backup nor selected SQLite can replace this fixed-root truth.
For this validation, a retained history/provenance epoch is first classified as either a locally
allocated epoch under allocator rule 18 or foreign immutable ancestry under rule 19. In the following
local-witness sentence, `retained history/provenance epoch ... in the same owner root` denotes only the
former and never the foreign immutable ancestry.
Every physically present selected pointer, retained history/provenance epoch, nonterminal intent, and
identifiable staged generation in the same owner root must carry the recomputed namespace and a serial
at or below the authenticated high-water; any higher or foreign value proves detectable journal
rollback/substitution and enters fixed-root corruption hold before SQLite or pointer selection. A
complete rollback of the owner root together with all such witnesses remains outside the supported
filesystem threat boundary and is not falsely claimed detectable.

The HMAC-bound checkpoint is a canonical, sorted lossless projection rather than an audit-history
shortcut. It contains checkpoint generation, covered head sequence/digest, format/key versions,
fixed-root safe-time/clock-hold and shutdown authority, active-state pointer certificate, recovery-ring
manifest, every live/null local command and portable reservation with its exact phase/safe result/
expiry authority, exactly four typed current/last addressed-state cells, every still-required resource provenance record, and the current fixed-root
coordinator if any. An open upgrade additionally carries its prepared source/target/certificate heads,
phase, interval-start sequence/digest, ordered allowed-lifecycle record count and rolling
domain-separated transcript digest, last covered sequence/digest, and the complete deterministic
clock/shutdown/command mirror projection. This projection is sufficient to recover and to apply the
same selected-state mirror without replaying removed bytes; it cannot authorize a record kind outside
the closed lifecycle/upgrade automata.

Each logical publication contributes exactly one canonical record with a gapless unsigned
`journal_sequence`, prior digest, domain-separated record digest, and HMAC. A bounded tail chains from
the checkpoint's covered head. Before a new record would exceed either tail cap, the coordinator folds
the existing tail plus that publication into a fresh checkpoint, recomputes the live projection and any
open-upgrade transcript accumulator, and emits an empty tail. It may fold during rollback eligibility,
clock hold, or `pending_escrow`; no live phase pins raw historical bytes. Expired/terminal authority is
omitted only when the projected rules already make it inactive. The one additional membership rule
closes a pending operation-`04` command: a terminal operation-`06` retirement record carries the exact
authenticated pending operation-`04` identity plus its generation/issuance facts, and the checkpoint
may omit that operation-`04` projection only when this covering operation-`06` record is authenticated
through the checkpoint's covered head; recovery-ring or key-file absence never proves closure. The
fold first authenticates the checkpoint and then the tail through that head, matches the carried
identity/generation/issuance facts to exactly one projected `secret_consumed` operation-`04` record,
and only then omits it; a missing, mismatched, or already-closed target returns `command_conflict`
before any journal, reservation, file, or ring mutation, and a second operation-`06` cannot close the
same projection. The unique pending operation-`04` plus its covering operation-`06` occupy at most two
of the 60 non-addressed reconciliation projections and at most five continuation records, within the
64-record bound. A resolved `upgrade_diverged` poison/
resolution pair freezes `audit_supported_until` from validated safe time using a configurable default
90-day window capped at 365 days. Folding may omit it only when that half-open boundary is at or below
the durable safe-time high-water and every named source/target/repaired generation is absent after
dependency-checked deletion. Unresolved, unexpired, or generation-dependent provenance survives byte-
for-byte semantically. Validation authenticates the checkpoint first and
then every remaining tail record through the checkpoint's covered head sequence/digest. A missing, duplicated,
reordered, transplanted, noncontiguous, or HMAC-invalid checkpoint/tail component is never skipped.

#### A-13.2.1. `control-journal-record/v1` envelope

The common tail-record envelope has one byte-exact v1 framing. It authenticates one opaque record body;
it is not a checkpoint codec, an image codec, or permission to apply a lifecycle transition. All integer
fields are unsigned big-endian. Let `L` be the frame's complete byte length and `B` its opaque body
length. `L = 110 + B`, `110 <= L <= 16,384`, and `0 <= B <= 16,274`; the maximum includes this framing,
as required by `MAX_CONTROL_RECORD_BYTES`. Every frame is exactly:

| Half-open bytes | Field |
|---|---|
| `[0,4)` | `L`: `U32BE`, including every byte in the frame |
| `[4,6)` | closed `kind`: `U16BE` |
| `[6,14)` | `journal_sequence`: `U64BE` |
| `[14,46)` | `prior_record_digest`: 32 raw bytes |
| `[46,L-64)` | opaque body bytes |
| `[L-64,L-32)` | `record_digest` `D`: 32 raw bytes |
| `[L-32,L)` | authentication tag `T`: 32 raw bytes |

The two full-width values are fixed exactly as follows; each ASCII label has no terminating NUL,
delimiter, or padding. `prior_record_digest` always names `D`, never `T`.

```text
D = SHA-256(
      ASCII("msgriver/control-journal-record/v1")
      || frame[4:L-64])

T = HMAC-SHA-256(
      journal_integrity_key,
      ASCII("msgriver/control-journal-record-auth/v1")
      || frame[0:L-32])
```

`T` therefore authenticates `L`, every fixed field, the body, and stored `D`; `D` independently gives
the stable chain identity over kind, sequence, prior identity, and body. The first envelope codec owns
this closed kind registry, whose codes are never derived from Rust enum order:

| `kind` | Record |
|---:|---|
| `0x0001` | `clock.checkpoint` |
| `0x0002` | `clock.acknowledge` |
| `0x0003` | `system.shutdown` |
| `0x0020` | `fixed_root.command/v1` |

Every other code, including zero, is invalid and is never skipped or represented as an unknown value.
This table assigns no code to upgrade or resource-provenance publications and no other command code;
every unlisted code remains invalid and requires an additive reviewed registry decision before an encoder
may produce it. The envelope alone accepts an empty body; the owning body codec and lifecycle automaton
later decide whether a body is semantically valid.

A trusted prior head is the pair `(s, d)`. Genesis alone is `(0, [0; 32])`; zero is never a record
sequence. A candidate must satisfy `journal_sequence == checked_add(s, 1)` and
`prior_record_digest == d`. `u64::MAX` is a valid final sequence, but a new publication after it is
unavailable: sequence never wraps, saturates, resets on restart, or resets when a fold leaves an empty
tail. A fold records the absorbed last `(sequence, D)` as its covered checkpoint head.

An envelope decoder first requires four bytes, bounds `L`, and requires `input.len() == L` before any
derived index, subtraction, allocation, or body access. It verifies `T` in constant time, recomputes
and verifies `D`, validates the closed kind and expected prior head, and only then returns authenticated
metadata with an opaque body. Any failure is closed, returns no partially parsed value, leaves the
caller's head unchanged, and never resynchronizes after invalid framing. An encoder applies the same
length, kind, and checked-head rules. A complete image remains responsible for authenticating the
checkpoint's covered head and terminal tail head/count/length; individual valid frames alone cannot
prove that a suffix or checkpoint was not removed or substituted.

Physically, every publication writes the complete next bounded image to a unique temp, fsyncs it,
atomically replaces the singular journal pathname, and fsyncs the fixed-root directory;
`RENAME_NOREPLACE` is not used for that replacement. Crash therefore selects exactly the old or new
complete authenticated image. Before a resource-growing fixed-root intent, the coordinator projects
that operation's maximum phase/final state against the ordinary byte/entry limits. Failure returns
`503 control_capacity` before staging, key generation, pointer/file mutation, or command reservation.
After admission, ordinary work cannot consume the reconciliation reserve; key-independent recovery,
one periodic/settlement/shutdown publication, addressed-state cell replacement, and capacity-reducing
command/ring/resolved-provenance retirement remain publishable. A fold-time provenance omission is the
single atomic full-image replacement itself; a crash selects the complete pre-retirement or post-
retirement checkpoint and never an unauthenticated intermediate.
The transition gate permits one coordinator, and the ring permits only one quiescent
`pending_escrow` successor, so live continuations cannot multiply beyond the proved projection.

The sole cross-operation ordinary-capacity reservation is A-10.7's
`upgrade_exit_capacity_binding`. `upgrade.prepare` is therefore in the exact fixed-root-journaled
operation registry even though its selected coordinator begins in normal mode. Its canonical binding
is HMAC-authenticated and losslessly folded with the open-upgrade projection; it fixes the target plan
digest, exact fixed-root journal format/framing/MAC-key format, per-role codec versions, and exact
maxima and consumed state for the migrate, ordinary-activate, dedicated-rollback, and forward-repair
roles. A binary with an incompatible bound format rejects continuation before consuming a role and
preserves the prior bytes and compatible rollback/recovery authority. Available ordinary entries and bytes are computed as physical live projection
plus every unconsumed bound amount, so unrelated work can never steal it. Role consumption is one
atomic authenticated image replacement and bypasses a second ordinary-capacity decision without
borrowing reconciliation space. The rollback role is not fungible. Prepare failure before a watermark
or a durable phase-ending selected-state mirror plus matching fixed-root terminal publication is the
only release authority. Restart, key-independent reconciliation, checkpoint fold, command expiry, and
caller-key loss preserve these invariants. A missing, smaller, reassigned, prematurely released, or
plan-mismatched binding while its coordinator or rollback eligibility exists is fixed-root corruption,
not a reason to reconstruct capacity from volatile or selected-state data.

<!-- upgrade-lifecycle-record-registry:start -->
The exact 3-record registry of non-upgrade lifecycle records that may interleave with A-10.7's
rollback-eligible upgrade automaton is: `clock.checkpoint`, `clock.acknowledge`, and `system.shutdown`.
The first is an autonomous, caller-key-free, single-phase terminal v1 record in the common sequence/
digest/HMAC envelope. It fixes runtime mode and process instance, the accepted wall/monotonic
observation, prior/new safe-time marker, the closed checkpoint reason (`periodic`,
`automatic_settlement`, `clean_shutdown`, or `expiry_proof`), hold generation/observation digest, and optional selected-
generation/pre-mirror transaction head; it carries no actor, operation, command-key, portable-
reservation, expiry, or resource identity. The latter two retain their cataloged addressed-state
authority and closed monotonic phase codecs, with no caller key or portable reservation. Its new marker may equal or exceed but never precede the prior
authenticated high-water. No other internal lifecycle record kind exists in v1.
<!-- upgrade-lifecycle-record-registry:end -->

#### A-13.2.2. `clock-checkpoint/v1` body

The opaque body of a `kind = 0x0001` lifecycle envelope has one canonical v1
codec. It is private journal state, not an API/CLI payload, a clock collector,
an acknowledgement, a selected-state mirror, or authority to write an image.
It closes only the body facts that A-11.5 and the lifecycle registry require a
checkpoint to preserve. Its complete length is either 53, 93, 125, or 165
bytes, depending only on the two explicit optional groups below; no trailing
or extension bytes are valid in v1. All signed integer fields use `I64BE` and
all unsigned integer fields use `U64BE`.

| Bytes | Field | Rule |
|---|---|---|
| `[0,1)` | `body_format` | `U8(1)` exactly |
| `[1,2)` | `runtime_mode` | `U8(1)` normal; `U8(2)` maintenance |
| `[2,18)` | `process_instance` | 16 opaque raw bytes; all-zero is invalid |
| `[18,26)` | `accepted_wall_time` | `I64BE` `UtcMillis` from the clock-guard-accepted observation |
| `[26,34)` | `accepted_monotonic_tick` | nonnegative `I64BE` `MonotonicTick` from that same observation |
| `[34,42)` | `prior_safe_time` | `I64BE` authenticated safe-time marker before this checkpoint |
| `[42,50)` | `new_safe_time` | `I64BE` authenticated safe-time marker after this checkpoint |
| `[50,51)` | `reason` | `U8(1)` periodic; `U8(2)` automatic settlement; `U8(3)` clean shutdown; `U8(4)` expiry proof |
| `[51,52)` | `hold_present` | `U8(0)` absent or `U8(1)` |
| `[52,53)` | `mirror_present` | `U8(0)` absent or `U8(1)` |

When `hold_present = 1`, bytes `[53,93)` are `hold_generation: U64BE` then
`observation_digest: [u8; 32]`. `hold_generation` is nonzero and the digest is
not all zero. They name exactly the opaque hold/observation address already
used by `clock.show` and `clock.acknowledge`; this body neither reveals the
raw sample nor creates, clears, or acknowledges a hold. `hold_present = 0`
has no placeholder bytes. When `mirror_present = 1`, the next 72 bytes start
at `53 + 40 * hold_present` and are `selected_origin:
OriginIncarnation[32]`, `pre_mirror_transaction_sequence: U64BE`, and
`pre_mirror_transaction_digest: [u8; 32]`. `selected_origin` must be a
structured allocated origin: its branch serial is nonzero, so the reserved
pre-bootstrap origin is invalid. `pre_mirror_transaction_digest` is not all
zero. They identify the selected generation and exact transaction head observed
before an allowed mirror; the checkpoint body does not perform or prove that
mirror.
`mirror_present = 0` has no placeholder bytes. The groups always appear in
hold-then-mirror order, and the exact body length is
`53 + 40 * hold_present + 72 * mirror_present`.

The body codec rejects an unknown tag, noncanonical optional-group layout,
all-zero opaque identifier/digest where prohibited, negative monotonic tick,
or a body length other than the four canonical lengths before returning a
value. It also invokes the A-11.5/Task-0018 transition rule: `new_safe_time`
must not precede `prior_safe_time`, and it is exactly
`max(prior_safe_time, accepted_wall_time)`. Thus a checkpoint carries the
accepted observation that justifies its durable high-water without allowing a
later implementation to replace the high-water with a lower wall reading.
`automatic_settlement` requires the named hold group; the other three reasons
require it absent. The body is representational rather than a publication
permit: A-11.5 permits a checkpoint during a clock hold only for automatic
settlement. A `periodic`, `expiry_proof`, or `clean_shutdown` checkpoint must
therefore be published only while no clock hold is current. The separately
typed `system.shutdown` lifecycle record—not a `clean_shutdown` checkpoint—is
the hold-permitted record of process truth and does not advance safe-time
fields.

The fixed 16-byte process instance is deliberately an opaque per-process
identity, not a caller, actor, command key, resource incarnation, or lease
fence. The two runtime tags are closed because A-13.3 and A-13.4 define the
only v1 composition roots. The observation and marker fields reuse A-04.1's
checked clock values and A-04.2's canonical `I64BE` convention. A fixed
`OriginIncarnation` plus transaction head makes the optional mirror witness
branch-safe without exposing selected state. This narrow body contract is the
predecessor of a private in-memory body codec; actual clock acceptance, hold
lifecycle, checkpoint projection, tail/image validation, atomic publication,
and selected-state mirroring remain `[PENDING]`.

Entries
store neither raw nor offline-guessable maintenance identifiers. Every bootstrap, blank-state restore,
generation transition, recovery-ring mutation, state-generation deletion, and upgrade activation/repair
persists and directory-fsyncs an intent *before* its first staging or state effect. The intent fixes
operation ID, stable actor namespace, local command-key digest/version, portable reservation
digest/version, base request/artifact or allowed phase fingerprints, source/target generation and
source/target history epoch/parent head when known, source runtime and accepting process instance, original deadline if applicable, a monotonic
phase, safe result, terminal time, and exact nullable command expiry. Runtime/process identity is not
part of either digest scope. Each phase/result update uses write-temp, file-fsync, atomic replacement
rename, and
parent-fsync. The journal is authoritative until a terminal safe result is retained; an active/selected
SQLite database mirrors both digests and safe command evidence idempotently but a crash between stores
cannot erase or duplicate authority. When selected state exists, maintenance may return a terminal
response only after that mirror commits. Normal startup reconciles any pointer-committed cross-store lag
from the authenticated journal into selected state before readiness or backup creation, ensuring every
unexpired/null portable reservation is present in the next artifact.

For `bootstrap.create`, `restore.create`, and `upgrade.rollback`, that first intent is also the sole
allocator transaction: it replaces the authenticated header with `branch_serial_high_water + 1` and
records the exact namespace/serial-derived target in one file-fsync/rename/parent-fsync publication.
The old image has neither fact and the new image has both. Later phases and same-intent recovery can
validate and reuse that target but cannot allocate; a different command begins only from the already
burned high-water. Continuation intents instead bind target equal to source and leave the allocator
fields byte-for-byte unchanged.

Clock acknowledgement and API-triggered shutdown instead persist and directory-fsync the A-13.2.4 addressed-state current cell before their first state effect. Its canonical actor, address, transition, evidence, phase/result, heads, and mirror union carry no caller command key, portable reservation, or expiry. Completion moves current to last only when terminal with mirror tag 0/2 and still eligible under that subsection's authority rules; terminal/tag 1 remains current until its mirror barrier resolves. A newer durable address cannot discard an unresolved obligation. Exact authorized retries disclose only the eligible address's safe phase/result, and other addresses return state_address_conflict. Authenticated replay, hold-entry invalidation, and hold-clear finalization preserve these rules across response loss, restart, and folding within exactly four cells.



Command entries and lasting resource provenance are distinct records in the authenticated journal.
Generated resource/transition/generation/key IDs carry rollback, recovery, ring, and artifact
dependencies after the command finishes; they contain no caller-key digest and outlive it as required.
A closed resource-provenance kind `upgrade_diverged` additionally binds one upgrade plus its
source/target generations, detecting phase, and expected/observed safe journal/store/certificate
heads/digests. Only A-10.7's exact `forward_repair` protocol may append its linked resolution; ordinary
command completion, cleanup, rollback, activation, or generation deletion cannot remove or overwrite an
unresolved record. A resolved poison/link pair is ordinary-capacity provenance until every named
generation is dependency-checked absent and its frozen `audit_supported_until` is at or below durable
safe-time high-water. Only checkpoint folding may then omit the pair as a capacity-reducing projection;
the full-image replacement is journaled by its new generation/head/HMAC and uses reconciliation
reserve. Repeated divergence/repair/delete/horizon cycles therefore do not monotonically consume the
projection, while a clock hold or remaining generation conservatively defers retirement.
A terminal caller-key entry leaves the journal's derived active result/reservation projection exactly at
the half-open `terminal_safe_at + configured_command_window` boundary even when authenticated history
or its resource record remains. Ordinarily, under the transition gate, physical active-index cleanup
and a same-tuple fresh intent are one atomic journal publication. During A-10.7's rollback-eligible
freeze, validated safe time plus the immutable expiry derives the same logical absence without command
cleanup or selected-state mutation. Before a response first relies on a crossing above the durable
journal high-water, A-11.5's allowed `clock.checkpoint` publishes that proof and its clock-only mirror;
failure returns unavailable. Once proven, no later hold or restart can restore result disclosure,
namespace conflict, portable reservation, or caller-key dependency, and a same-tuple request is fresh
but still blocked by the upgrade hold. The
selected hold-clear transaction deletes its SQLite mirror and verifies the derived journal projection
before effects; superseded tail bytes may fold into the bounded checkpoint at any publication. A null-
expiry effect-bearing or pending-escrow command never ages out, and bounded cleanup never removes the
only phase authority/result. Portable MAC generations remain through every active record and any frozen
hold-clear verification that names them; local resource provenance never extends logical caller-key
reservation lifetime. All expiry comparisons use A-11.5 validated safe time. A clock hold makes only a
null expiry or boundary above the durable high-water provisionally unexpired; proven-expired authority
stays absent, and every fresh-effect reuse remains forbidden.

Maintenance startup, every later fixed-root mutator admission, and every streaming-handler/input failure
run the same key-independent coordinator over any effect-bearing entry before accepting another
mutator. A caller-requested ordinary `command_key` resume requires the same command/body digest; the
coordinator's key-independent finish/rollback is recovery of recorded intent, not a new request. A
`one_time_secret` entry instead keeps
one immutable issuance digest plus tagged phase digests: same-key `generate` must match the original
generation parameters, while `acknowledge` is the sole permitted different tag/body and must match the
recorded confirmation digest; every other variation conflicts. Reconciliation finishes every prefix
whose complete durable input/effect is available. If required caller bytes are absent and no activation/
irreversible effect occurred, it removes only that intent's checked staging, fsyncs the parent, publishes
terminal `input_abandoned`, and releases the transition gate; a different key may then start immediately
while the old key receives that terminal result until expiry. It never selects a generation by directory-
name guess. A blank restore intent is durable before upload and records declared artifact length/digest;
disconnect/inactivity discards and terminalizes an incomplete upload, while a complete verified staging
artifact is finished by the coordinator without needing the caller key. A shutdown with no active database
reaches a terminal prior-process result through this journal exactly like an active-state shutdown; it
never re-triggers against the new process.

Before any fixed-root intent/effect, maintenance computes the incoming tuple under the current local key
and every bounded portable generation available from the fixed root/selected state. A current local
match follows normal same-key semantics. A portable match whose source runtime differs returns
`command_namespace_changed` through its exact expiry without trusting or disclosing the mirrored
result. Bootstrap copies the pre-bootstrap portable key and unexpired/null reservations into its first
state generation. Restore checks decrypted artifact reservations before pointer mutation and unions the
artifact, current proven-descendant, and new-host portable generations/rows into staged state, so even a
pre-bootstrap foreign command remains collision-detectable after activation.

The fixed-root recovery ring is independently usable before bootstrap or during blank-host restore and
contains immutable final key files. Generate/import/retire uses a caller command key and the control
journal: after durable intent it creates/renames or removes and directory-fsyncs the mode-`0600` key
file, then publishes the safe result. Reconciliation regenerates a missing generated file only if no
secret could have been released, finalizes a completed file, and never removes a key before dependency
validation is durable.
The maintenance transition gate excludes configuration, state-key, recovery-key, restore, upgrade,
state-generation deletion, and shutdown mutators while any one protocol runs.

A generated recovery key begins `pending_escrow`. The ring admits at most one such successor; a second
generate returns `409 recovery_key_pending_escrow` before journal intent or key-file creation. Its protected request codec is a closed tagged union:
`generate` carries the command key and generation parameters; `acknowledge` carries the same command
key plus exact confirmation digest. The first protected response contains the secret once plus safe
metadata/digest. After the key file and result metadata are durable, the journal advances to
`secret_consumed` before writing response bytes, so response loss can never make a retry disclose it
again. A same-key retry at or after that phase returns only pending metadata/digest. The CLI stores the
secret and auto-acknowledges only after A-08.3's exclusive write, file fsync, parent fsync, reopen, and
digest verification. Stdout/pipe/descriptor output cannot auto-ack; an API caller or operator may send
the explicit `acknowledge` variant only as an assertion that equivalent durable escrow has completed.
Acknowledgement activates the generation and demotes the prior active generation to retained in the
same journaled ring publication, without returning secret bytes. There is never a two-active prefix:
before the atomic ring-manifest rename the predecessor is active; after it the successor is active.
If `acknowledge` finds no matching generated tuple, it returns `command_conflict` before creating a
command entry, reservation, file, or ring mutation. That miss does not consume the command key, so a
later `generate` using it is evaluated as fresh.

By invariant, `pending_escrow` is never active, backup-selectable, or referenced by retained local
artifact evidence. Crash at or after `secret_consumed` reconciles to a visible quiescent pending
record rather than regenerating or guessing delivery. The generation is therefore dependency-free and
`recovery_key.retire` may remove it with its ordinary explicit deletion confirmation and command key;
it does not require an impossible escrow acknowledgement or artifact-dependency override. A lost
response thus strands only replaceable random material, never the ring or future backup operation.
The quiescent pending journal record releases the transition gate but is retained until exact
acknowledgement activates it or a separately keyed retirement records that it was removed; ordinary
age-based journal cleanup cannot erase that phase authority.
Import proves that the caller already possesses the secret and may activate it in one command, using
the same atomic successor/predecessor state transition. Backup creation rejects the absence of exactly
one active recovery generation. Lost escrow makes an older artifact
naming that generation honestly unrestorable. Retirement of an active/retained generation is rejected
while a local artifact requires it; declaring all externally copied artifacts disposed requires the
exact explicit destructive acknowledgement in the catalog codec.

All keys use CSPRNG bytes, no-follow/exclusive creation, mode `0600`, file and containing-directory
fsync before reference, and redacted zeroizing wrappers. No log, error, panic formatter, catalog, or
metric receives secret bytes.

API-key issue and rotation generate 32 random secret bytes in the service, persist only the keyed
verifier, and serialize the plaintext once into the protected response. The plaintext is cleared after
serialization and is neither retryable nor recoverable after response loss; safe key metadata makes
the orphan visible so an operator can revoke it and issue another. Rotation creates a distinct key,
optionally marks the predecessor `retiring` for a bounded overlap, and never mutates the principal.

#### A-13.2.3. `fixed_root.command/v1` common body

`kind = 0x0020` is the one generic body family for every fixed-root
`command_key` or `one_time_secret` record. The two addressed-state operations
remain outside this family. Its literal v1 operation codes are `01`
configuration activation, `02` state-key rotate, `03` state-key retire, `04`
recovery-key generate, `05` recovery-key import, `06` recovery-key retire,
`07` bootstrap create, `08` restore create, `09` state-generation delete,
`0a` upgrade prepare, `0b` upgrade migrate, `0c` upgrade activate, and `0d`
upgrade rollback. Zero, every other code, and an enum/catalog-derived value
are invalid.

The complete v1 structural prefix is below. Every optional tag is decoded
before its associated bytes are sliced; a false tag has no placeholder bytes.

| Field | Encoding and rule |
|---|---|
| format / operation | `U8(1)` then the one literal operation code above |
| actor | `U8` kind then `U8` length `1..128` then exactly that many bytes; kind `1` is a raw ASCII principal ID valid under the identifier grammar and kind `2` is exactly ASCII `msgriver/state-owner/v1` |
| four command tags | in exact purpose order `06`, `07`, `08`, `0b`, each raw `MacKeyId[40]` then its 32-byte tag |
| runtime / process | `U8(1)` normal or `U8(2)` maintenance, then a nonzero opaque `[16]` process instance |
| original deadline | `U8` presence `0` or `1`; when present, one `I64BE` deadline |
| profile phase | nonzero `U16BE` |
| retention / terminal | retention `U8(1)` continuation or `U8(2)` terminal, then `U8` terminal-time presence and, when present, one `I64BE` terminal time; then `U8` expiry presence and, when present, one `I64BE` expiry |
| safe result | `U8` presence `0` or `1`; when present, `U16BE` codec, `U16BE` version, and raw digest `[32]` |
| target binding | `U8` presence `0` or `1`; when present, raw source and target `OriginIncarnation[32]` values; `U8` source-generation presence plus optional `U64BE`; `U8` target-generation presence plus optional `U64BE`; and `U8` parent-witness presence plus optional parent `OriginIncarnation[32]`, parent head `U64BE`, parent head digest `[32]`, and parent certificate digest `[32]` |
| profile body | `U16BE` body length then exactly that many opaque profile bytes |

The largest prefix, including a 128-byte actor and every optional group, is
694 bytes. Therefore `prefix + profile_body <= 16,274` and the profile body is
at most 15,580 bytes. Unknown tags, zero actor length, zero process instance,
zero phase, and noncanonical optional layout are invalid before body decoding.
For a continuation, both terminal-time and expiry presence tags are zero; it
cannot age out. For a terminal, both tags and safe-result presence are one,
and `command_expires_at > terminal_time`. An allocating profile requires a
target binding; a continuation requires target equal to source. Operations
`04`, `05`, and `06` are non-allocating and uniformly encode absent target
binding. That absence is immutable across every publication of one command
identity: the continuation source-equals-target rule is inapplicable by this
profile rule rather than inferred from a zero origin, and no later phase may
introduce a binding. A present binding keeps both origins structured nonzero
allocated origins except bootstrap's source, which is exactly
`PreBootstrapOrigin`; no other serial-zero origin is valid.

The actor identity in all command tags is `actor_kind || actor_bytes`. Each
HMAC input begins `ASCII(domain) || NUL || MacKeyId[40]`; `LP32(x)` is exactly
one `U32BE` byte length followed by `x`, and every listed field has its own
`LP32`. Purpose 06 uses domain
`msgriver/fixed-root-command-lookup/v1` and suffix
`LP32(operation_code) || LP32(actor_identity) || LP32(caller_command_key)`.
Purpose 0b uses domain `msgriver/fixed-root-portable-reservation/v1` and that
identical suffix. Purpose 07 uses domain
`msgriver/fixed-root-command-semantic/v1` and suffix
`LP32(operation_code) || LP32(U16BE(codec_id) || U16BE(codec_version)) ||
LP32(operation_canonical_request_bytes)`. Purpose 08 uses domain
`msgriver/fixed-root-command-phase/v1` and the same first two fields followed
by `LP32(operation_canonical_phase_bytes)`. The portable tuple may use
`PreBootstrapOrigin`. Runtime/process, profile phase code, safe result,
allocator facts, and expiry are outside all four tag scopes. The known-answer
vectors for these exact preimages remain versioned in Task 0062 and the frozen
RED fixture; they are conformance evidence, not an alternate framing source.

Every profile's least phase is `intent`; its closed nonzero phase table has
strictly increasing transitions and absorbing terminals. A terminal requires
exact `command_expires_at = terminal_safe_at + configured PR-075 window`; at
or after that boundary the record and both reservations are logically absent.
`secret_consumed` is always a continuation published before plaintext response
bytes. A result reference identifies separately held canonical safe bytes,
never response plaintext or a body.

Operation `04` fixes the first literal profile. Its phase table is `0x0001 intent` and `0x0002
`secret_consumed` (continuations) plus `0x0003 acknowledged` and `0x0004 input_abandoned` (terminals);
the only permitted edges are intent→secret_consumed, intent→input_abandoned, and
secret_consumed→acknowledged, and recovery-key retirement remains operation `06`, never an
operation-`04` phase. Its canonicalizer is `U16BE 0x0075` with version `U16BE 0x0001`; that pair names
both the purpose-`07` and purpose-`08` preimage codec. Canonical request bytes are exactly
`ASCII("msgriver/recovery-key-generate/v1") || U8(variant) || U8(1)` for the generate variant, whose
v1 parameter domain is empty, or that label followed by `U8(2) || D[32]` carrying the exact
confirmation digest for the acknowledge variant. Canonical phase bytes are exactly
`ASCII("msgriver/recovery-key-generate-phase/v1") || U8(4) || U16BE(from) || U16BE(to) || U8(mask)`,
where mask bits `0` and `1` record issuance and confirmation presence. The profile body is exactly
`U8(1) || U8(variant) || U8(field_count)` followed in canonical kind order by `U8(kind) || D[32]`
entries; kinds `1` and `2` are the issuance and confirmation digests and never share one slot. The
body is at most 69 bytes, so `694 + 69 = 763 <= 16,274` opaque body bytes and an `873 <= 16,384`
envelope hold. Held safe results use codec `U16BE 0x0076`, version `U16BE 0x0001`, in secret-free
pending, activation, and abandonment forms; `secret_consumed` is the irreversible boundary: before it
the coordinator may finish or reconcile, after it response plaintext is never replayed.

The checkpoint contains exactly one lossless projection for every null-expiry
or unexpired command, keyed by operation, actor identity, purpose-06 key ID,
and command tag; its purpose-0b identity/tag is part of that same projection.
It retains common authority and profile bytes/a lossless profile reference.
Checkpoint wire, fold order, result store, and profile body/phase tables remain
separately versioned decisions.

#### A-13.2.4. `addressed_state/v1` checkpoint cells and lifecycle actions

The fixed-root addressed-state registry remains exactly `clock.acknowledge` and
`system.shutdown`, outside `fixed_root.command/v1`. Its checkpoint projection
contains exactly four members in order: acknowledge-current (tag 7),
acknowledge-last (8), shutdown-current (9), shutdown-last (10). Each member is
`U16BE tag || U32BE body_length || body`. The only body forms are the single byte
`00` for absence and the populated request forms below. All four genesis bodies
are absent. Missing, duplicate, reordered, or unknown addressed-state tags are
invalid before projection exposure.

Current-address authority exists outside these request cells: the clock-authority
member supplies the current hold, and authenticated lifecycle startup
reconstruction supplies the newest process instance. There is no address fence.
Hold generations strictly increase, and process instances are never reused.

Every populated cell carries `U8 actor_kind || U8 n || actor_bytes[n]`, with
`1 <= n <= 128`. Kind 1 is the raw ASCII principal ID matching
`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`; kind 2 is exactly the 23 ASCII bytes
`msgriver/state-owner/v1`. Unknown kinds, invalid lengths, invalid principal
bytes, or a non-exact state-owner value are rejected before address/result
decoding. Absent cells carry no actor. The actor records attribution; retry
disclosure is address-scoped and does not require the retrying actor to equal the
recorded actor. Every request and disclosure first rechecks authentication and
current authorization.

All integers below are big-endian. Signed clock values use `I64BE`; opaque byte
arrays have exactly the stated width. Optional tags and booleans are closed `U8`
values 0 or 1, and absent fields have no placeholder bytes.

| Acknowledge cell field, in byte order | Canonical encoding |
|---|---|
| Format and operation | `U8(1) || U16BE(0x0002)` |
| Actor | `U8 actor_kind || U8 n || actor_bytes[n]` |
| Address | Nonzero `U64BE hold_generation || observation_digest[32]`, with a nonzero digest |
| Desired transition | `U8(1)` settle named hold, then `U8(1)` explicit risk acknowledgement |
| Evidence | `I64BE accepted_wall_time || I64BE accepted_monotonic_tick || I64BE prior_fixed_safe_time || U8 prior_selected_present || [I64BE prior_selected_safe_time]? || I64BE target_safe_time` |
| Phase | `U8` from the acknowledge phase table |
| Safe result | The exact 15-byte `0x0077` result below |
| Fixed-root heads | `Happlication || Hpublication`, 40 bytes each |
| Selected mirror | The tagged union below |

The accepted monotonic tick is nonnegative. Evidence occupies 33 bytes without
selected state or 41 bytes with it. `target_safe_time` equals exactly
`max(prior_fixed_safe_time, prior_selected_safe_time when present,
accepted_wall_time)`. Absent prior selected time requires mirror tag 0; present
prior selected time requires tag 1 or 2.

| Shutdown cell field, in byte order | Canonical encoding |
|---|---|
| Format and operation | `U8(1) || U16BE(0x0003)` |
| Actor | `U8 actor_kind || U8 n || actor_bytes[n]` |
| Address | Nonzero opaque `process_instance[16]` |
| Desired transition | `U8(1)` stop named process, then nonzero `U32BE grace_ms` |
| Evidence | Nonnegative `I64BE accepted_monotonic_tick || I64BE grace_deadline_tick` |
| Phase | `U8` from the shutdown phase table |
| Safe result | The exact 7-byte `0x0078` result below |
| Fixed-root heads | `Happlication || Hpublication`, 40 bytes each |
| Selected mirror | The tagged union below |

The shutdown deadline is exactly the checked, no-wrapping sum
`accepted_monotonic_tick + grace_ms`; overflow is invalid. No separate runtime
or accepting-process field is encoded.

| Operation | Phase | Meaning | Legal next phase |
|---|---:|---|---|
| Acknowledge | 1 | Accepted input durable | 2 |
| Acknowledge | 2 | Fixed-root settlement progress durable; hold retained | 3 |
| Acknowledge | 3 | Terminal acknowledged | None |
| Shutdown | 1 | Accepted request durable | 2; recovery-only 4 |
| Shutdown | 2 | Named process stopping | 3 or 4 |
| Shutdown | 3 | Terminal graceful | None |
| Shutdown | 4 | Terminal ungraceful | None |

Transitions never skip a phase except shutdown's explicit recovery-only 1→4
edge. Acknowledgement failure leaves the prior phase recoverable. Shutdown's
phase-4 reason is exactly one of `U8(1)` process disappeared, `U8(2)` grace
exhausted, `U8(3)` safe checkpoint failed, or `U8(4)` safe stop coordination
failed. Every other shutdown phase requires reason `U8(0)` none.

Each populated cell contains one inline result with no presence tag or duplicate
phase:

- Acknowledge: `U16BE(0x0077) || U16BE(1) || U16BE(9) || I64BE settled_safe_time || U8 settled`.
  The time equals the evidence target, and `settled` is 1 exactly in phase 3.
- Shutdown: `U16BE(0x0078) || U16BE(1) || U16BE(1) || U8 ungraceful_reason`,
  consistent with the phase table.

`deadline_derivation_pending` is not stored in the cell. Disclosure derives it
from mirror tag/policy and A-13.2's existing deterministic clock/shutdown/command
mirror projection. Policy 2 remains pending until its designated hold-clear
transaction; `commit_mirror` does not clear that pending derivation. These are
private projection and retry facts, not a claim that blocked public response
schemas are complete.

Each fixed-root head is `U64BE sequence || digest[32]`. Both are authenticated
non-genesis journal heads. `Happlication` names the record that produced the
current phase and is immutable within that phase; `Hpublication` names the
record that last made cell bytes durable. Phase production sets both to that
record's head. A later mirror receipt that does not change phase advances only
`Hpublication`. Application sequence cannot exceed publication sequence; equal
sequences require equal digests. At a folded checkpoint, both heads are no newer
than the authenticated covered head, and equality in sequence requires its exact
digest.

| Mirror tag | Complete width | Bytes following the tag |
|---:|---:|---|
| 0 | 1 | None; selected state not applicable |
| 1 | 74 | `OriginIncarnation[32] || Hpre[40] || U8 policy`; pending |
| 2 | 114 | `OriginIncarnation[32] || Hpre[40] || U8 policy || Hpost[40]`; committed |

The origin is structured with nonzero branch serial. `Hpre` and `Hpost` are
selected transaction heads, each `U64BE sequence || digest[32]`, with nonzero
digests and `Hpost.sequence > Hpre.sequence`. Policies are exactly 1 ordinary
clock settlement, 2 rollback-eligible clock-only settlement, and 3 shutdown.
Acknowledge admits only policies 1/2; shutdown admits only policy 3.

Only `publish_request` creates tag 0 or 1, with tag 0 exactly when no selected
state exists at request publication. Tag-1 origin, pre-head, and policy remain
unchanged through every phase until `commit_mirror`; phase publication neither
resets nor creates mirror bytes. The mirror binds the current application head
and exact operation/address/phase/projection facts. It records mirror state, not
proof of selected-store commit; this contract introduces no selected-store
verifier or evidence codec.

Existing envelope kinds `0x0002` and `0x0003` carry the following closed action
body, without changing A-13.2.1 framing:

`U8(1) || U8 action || U16BE payload_length || payload`

| Action | Exact payload | Preconditions and projection effect |
|---|---|---|
| 1 `publish_request` | Canonical populated request body with both 40-byte fixed-root heads omitted | External authority names the request address; prior obligations are resolved. Installs phase 1 in current with mirror tag 0/1, never 2, and both heads supplied by this envelope. |
| 2 `publish_phase` | `U8 new_phase || result` | Applies one legal edge to a nonterminal tag-0/1 cell; updates phase/result and both heads while preserving mirror bytes. Acknowledge 2→3 is legal only with tag 0. Shutdown 1→4 is recovery-only. |
| 3 `commit_mirror` | `Hpost[40]` | Requires acknowledge phase 2/tag 1, or shutdown terminal phase 3/4 with tag 1. Commits tag 1→2. For acknowledge, it also produces phase 3 and supplies both heads; for shutdown, it preserves the terminal-producing application head and advances publication only. |

All other action codes and layouts are invalid. A committed mirror exists only in
a terminal cell and never crosses an application-head change. Acknowledge phase
3/tag 1 is unreachable. Shutdown terminal/tag 1 is valid progress, but cannot
disclose a complete result or move to last until its mirror barrier resolves. For
either operation, only terminal tag 0/2 can disclose completion.

Request publication is durably directory-fsynced before the first state effect
and changes no clock authority. Acknowledge 1→2 raises fixed-root safe time
under the current-address and nondecreasing-high-water guards but retains the
hold. Shutdown publications change neither clock hold nor safe time.

For acknowledge tag 0, legal `publish_phase(3)` is the fixed-root
settlement-effective publication. For tag 1, `commit_mirror` is its counterpart
with the required selected-state FULL mirror barrier. Every hold-clearing
publication, including automatic settlement, atomically finalizes every pending
acknowledge obligation for that same address in the authenticated full-image
replacement. Retain/drop reads the **pre-publication** clock authority: retain
completion only when it names that exact hold; drop the old obligation to absence
when it names a greater generation or is absent. Only an exact matching hold may
be cleared. An older settlement cannot clear or lower newer authority. Every
crash prefix before the required completion barrier retains the hold and starts
no attempt.

After authentication and current authorization, read external authority before
cell lookup. An exact address/transition retry of its current cell returns the
same safe phase/result without another effect. A different desired transition
for that same current shutdown process returns `shutdown_in_progress`. An exact
acknowledge-last retry is eligible when clock authority names its address or is
absent; another hold conflicts. An exact shutdown-last retry is eligible only
before a newer process becomes current. Every other older, future, or different
address returns `state_address_conflict` without older-result disclosure. Absent
clock authority never authorizes a fresh acknowledgement.

A nonterminal cell or any tag-1 cell is an obligation. It survives every fold
with its own exact mirror and projection facts, even when its address is obsolete
and therefore undisclosable. A newer request must resolve that obligation through
the existing recovery/mirror barrier or fail closed before replacing it. Retained
clock authority/high-water is settlement input, not a substitute carrier for
lost mirror facts. Eligible terminal tag-0/2 completion moves current to the
single last slot and makes current absent; superseded completion drops to
absence. New request installation replaces only the resolved prior state of its
own operation, in one authenticated publication after the new external address
is durable.

A hold-entering publication atomically evicts any older completed
acknowledge-last cell. The hold-clear finalization ordering prevents an old
obligation from surviving a newer hold's clearance and later restoring retry
eligibility. Thus H1 completion is retained only if finalized before H2 becomes
durable, and cannot reappear after H2 clears or after folding. This uses existing
member occupancy and publication ordering, with no historical carrier. Startup
resolves an old shutdown obligation honestly after fence recovery; it never
executes that request against the new process.

Validation authenticates outer framing and bounds, requires the exact ordered
member inventory, checks canonical field lengths/tags and actor grammar, then
checks operation/slot, address, evidence, phase/result, mirror/policy, and head
consistency. It classifies cells as current, eligible completed, or
recovery-retained obligations without treating retention as disclosure authority.
Authenticated tail replay checks each action's legality and exact phase-producing
head in a temporary projection; all cross-field and authority rules are
revalidated before atomic exposure. Invalid framing, arithmetic overflow,
truncation, trailing bytes, or any failed cross-check yields no partial
projection and no effect.

For actor length `n`, acknowledge body length is `143 + n + E + M`: 178–305
bytes with tag 0, 259–386 with tag 1, or 299–426 with tag 2. Shutdown body
length is `130 + n + M`: 132–259, 205–332, or 245–372 bytes respectively.
Including six-byte member framing, maximum acknowledge/shutdown members are
432/378 bytes; all four occupy at most `2 × 432 + 2 × 378 = 1,620` bytes and
exactly four entries of the existing 64-entry/2-MiB reconciliation reserve.
Genesis occupies `4 × (6 + 1) = 28` bytes. Phase-1 requests cannot carry tag 2,
so the largest request frame is `110 + 4 + (386 − 80) = 420` bytes; 128 such
frames occupy 53,760 bytes, below both existing tail bounds.

This contract adds no fifth slot, unbounded history, address fence, caller key,
command-key digest/MAC tag, portable reservation, command expiry, reuse
namespace, or lease authority. It changes no operation registry, envelope kind,
generic command body, reserve, public API/CLI binding/path, SQLite schema, or
public JSON schema, and supplies no selected-store verifier.


#### A-13.2.5. `state-mac-key/v1` selected-ring value and bootstrap image

The state-key ring manifest has one row for every retained key identity. A row
is exactly the A-10.2.1 `MacKeyRef` columns plus `status` and validated-safe
`created_at`; it has no surrogate key, raw secret, caller value, display
name, or mutable active-pointer path. `status` is closed: `1=active` and
`2=retained`. Rows are sorted by `(purpose byte, origin bytes, serial)`.
There is exactly one active row per purpose and at most sixteen rows per
purpose. An active row uses the selected origin except the one portable
purpose-`0b` row, which is the copied `PreBootstrapOrigin` key. Unknown
purpose/status, zero serial, duplicate reference, missing active row, more
than sixteen purpose rows, or another active foreign-origin row is corruption.

Bootstrap creates one active serial-one internal entry under its allocated
origin for purposes `01..0a`. Its selected-origin high-water vector is one for
those ten purposes and zero for `0b`. It copies the fixed-root portable `0b`
entry unchanged as the sole active portable entry. It also copies the existing
pre-bootstrap serial-one `06`/`07`/`08` entries as retained verification
entries; they may be unreferenced by the initial empty selected database and
do not contribute to selected-origin high-water. This is the only initial
exception to active-selected-origin membership. A later dependency check
governs retirement, not whether an initial retained verifier may be present.

Every purpose-qualified path contains exactly one private 106-byte
`state-mac-key/v1` value:

```text
U8(1) || MacPurpose[1] || MacKeyId[40] || raw_key[32] ||
HMAC-SHA-256(journal_integrity_key,
  ASCII("msgriver/state-mac-key/v1") || preceding 74 bytes)
```

The raw key is exactly 32 nonzero bytes. Decode requires exact length, verifies
the tag in constant time, then validates format, closed purpose, nonzero
serial, and equality with the manifest row and derived path before exposing
the raw key to the private MAC provider. This is a domain-separated use of the
host-local journal key; it does not give that key a `MacKeyId`, put it in the
ring, or relax R3-INV-110. A key-file HMAC is distinct from a state MAC and
does not authorize any caller operation.

Before pointer publication, bootstrap reopens the staged image and verifies
the header selected origin, the complete high-water vector (`01..0a=1`,
`0b=0`), the canonical manifest, each no-follow owner-only exact-length file
and HMAC, every derived path, and all SQLite `MacKeyRef` references together.
An absent/mismatched/duplicate/extra file or invalid tag rejects the staged
image. An unreferenced initial retained verifier alone does not. The staged
SQLite transaction, key-file fsyncs, generation directory fsync, and parent
directory fsync all precede the sole active-state pointer commit.

#### A-13.2.6. `state_mac_keys` manifest schema and safe-time boundary

Every selected-state generation stores its state-key manifest in exactly one
`state_mac_keys` SQLite table:

```sql
CREATE TABLE state_mac_keys (
    purpose INTEGER NOT NULL CHECK (purpose IN (1,2,3,4,5,6,7,8,9,10,11)),
    origin BLOB NOT NULL CHECK (length(origin) = 32),
    serial_hi INTEGER NOT NULL CHECK (serial_hi BETWEEN 0 AND 4294967295),
    serial_lo INTEGER NOT NULL CHECK (serial_lo BETWEEN 0 AND 4294967295),
    status INTEGER NOT NULL CHECK (status IN (1,2)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (purpose, origin, serial_hi, serial_lo),
    CHECK (serial_hi != 0 OR serial_lo != 0)
) WITHOUT ROWID;
CREATE UNIQUE INDEX state_mac_keys_one_active_per_purpose
    ON state_mac_keys (purpose) WHERE status = 1;
```

The table has no surrogate identity, raw key, display name, caller value, path,
or mutable active pointer. Its reference reconstructs exactly as
`MacKeyId = origin[32] || U32BE(serial_hi) || U32BE(serial_lo)`. The canonical
reader orders rows by `(purpose, origin, serial_hi, serial_lo)` and rejects an
unreadable type/length/range/status/reference before it opens a key file or
constructs a provider. The partial unique index enforces one active row per
purpose; the selected-state key-ring validator separately enforces the
sixteen-row bound, the selected/pre-bootstrap origin exception, canonical
order, high-water agreement, and header/file cross-agreement.

`created_at` is a signed `i64` millisecond value supplied only by the
selected-state coordinator after A-11.5 has obtained a validated safe-UTC
instant. A writer stores that exact value. A reader preserves the exact signed
value but never reads a clock or asserts freshness; a non-integer SQLite value
is corruption. Thus the manifest does not recreate time authority, while every
stored creation instant remains tied to the validated-safe coordinator input.
SQL shape/decoding and the active index are store-owned. Image-level
cross-agreement remains a selected-state key-ring validation step, so no table
row alone authorizes a key file or active-state pointer.

#### A-13.2.7. `state-mac-key/v1` complete staged directory verification

The state-key namespace inside an already-opened, separately validated staged
generation is exactly `mac/` with the eleven direct owner-euid mode-`0700`
directories `01` through `0b`. Each is opened and verified by descriptor with
`DIRECTORY|NOFOLLOW|CLOEXEC`; directory link count is not an acceptance
criterion. Each purpose directory contains exactly the direct `mk_` basename
derived from every canonical manifest row of that purpose and nothing else.

The bounded verifier retains those descriptors, ignores only the directory
reader structural names `.` and `..`, and rejects every other unexpected or
repeated name immediately. It separately rejects duplicate expected names,
missing expected names, a non-directory intermediate entry, link, nonregular
key entry, incorrect owner/mode/link count/length, inode replacement, or
invalid key-file HMAC. It has at most eleven purpose directories and sixteen
expected names per purpose, never recurses beyond those two levels, and proves
exact equality between the bounded observed and manifest-derived name sets.
Every decoded key and raw file buffer is zeroized on success and every failure;
the verifier returns only success or a redacted failure and constructs no ring
or `MacProvider`.

The existing exclusive state-owner lock remains held from this descriptor-bound
scan through the sole pointer-publication decision, and no other writer gains a
mutable descriptor for the staged generation. The scan is only one required
input: under that same exclusion the publication coordinator also verifies the
canonical manifest, every derived key-file path, and all SQLite `MacKeyRef`
references before the pointer may name the generation. The scanner neither
acquires the lock nor discovers a root, chooses a generation, queries SQLite,
derives pre-bootstrap state, bootstraps, publishes a pointer, creates a
provider, starts service, releases, publishes, or tags.

### A-13.3. Normal mode

`msgriver serve` performs, in order: restrictive umask and core policy; state lock; configuration and
secret validation; database profile/integrity/schema compatibility; restored/upgrade/clock/storage hold
reconstruction; adoption of systemd-preopened UDS/TCP sockets; then scheduler/workers. Readiness remains false
until all preconditions finish. Provider connectivity is not a startup precondition.

Only normal mode dispatches effects. It owns the main socket and cannot bind the maintenance socket.
Graceful termination closes listener/effect admission through a separate shutdown hold without writing
the operator-admission row, records drain/shutdown intent, and bounds worker completion without
forgiving a dispatching lease, checkpoints within its space/time budget, removes sockets, and releases
the owner lock last. Authenticated `system.health` exposes the current opaque process instance.
`system.shutdown` requires that exact `expected_process_instance` and desired grace, then records its
addressed-state current cell with process instance, grace deadline, and `accepted` phase in the fixed
control journal, and mirrors it in SQLite when active state exists. The maintenance operation therefore has the same retry semantics before bootstrap or
blank restore. An always-on supervisor observes that durable phase and invokes the coordinator
independently of whether the handler's `202` write succeeds; response delivery is
never a trigger. During clock hold this lifecycle record is allowed but does not advance safe-time
fields, expire/clean another record, or release/provider-dispatch work. Exact newest-current process-
address retries, or its completed result before a later process starts, return the same phase/result; a different address receives `state_address_conflict`,
while a second desired transition for the same active process receives `shutdown_in_progress`. If the process crashes first, startup records the old shutdown obligation as terminal phase 4 with an honest closed ungraceful reason after fence recovery; it never replays shutdown against the new process. A terminal/tag-1 cell remains current, undisclosable while the newer process is current, until the existing selected-mirror barrier resolves; it cannot be replaced or disclosed as complete while pending. Recovery applies A-13.2.4's terminal tag-0/2 completion rules before admitting the newer process's request. No old shutdown result becomes retryable against that newer process. The systemd unit does not restart a clean zero-status coordinator exit;
subsequent host starts are new lifecycle actions. SIGTERM invokes the same coordinator without creating
a second state-transition implementation. Under clock hold, an injected monotonic grace budget may only
decide a safe lifecycle success or nonzero shutdown failure for the current process; it never declares a
persisted UTC deadline or lease expired. Maintenance exposes the same operation and coordinator without
workers.

### A-13.4. Maintenance mode

`msgriver maintenance serve` is a separate composition root in the same binary. It requires the
dedicated service account for the process, acquires the normal state lock, accepts only the root-owned
mode-`0600` systemd-preopened maintenance UDS, and authenticates the accepted peer UID before HTTP
parsing. The first-slice state owner is exactly connecting UID 0; the service process UID is never
treated as that caller. It ignores bearer credentials and does not load provider credentials.
It receives only the read-only metadata-directory descriptor and opens the fixed
`SecretReferenceCatalog` basename after taking the owner lock, so configuration and restore validation
can prove current name existence without a secret path or value oracle.

<!-- maintenance-operation-registry:start -->
Its exact 23-operation registry is the maintenance-binding subset of `specs/operations.toml`:
`configuration.show`, `configuration.validate`, `configuration.activate`, `state_key.list`,
`state_key.rotate`, `state_key.retire`, `recovery_key.list`, `recovery_key.generate`,
`recovery_key.import`, `recovery_key.retire`, `bootstrap.create`, `restore.create`, `restore.show`,
`state_generation.list`, `state_generation.delete`, `upgrade.show`, `upgrade.migrate`,
`upgrade.rollback`, `clock.show`, `clock.acknowledge`, `system.health`, `system.readiness`, and
`system.shutdown`. Every other path is
absent, not merely authorization-denied. One exclusive transition gate serializes every operation that
can replace/delete a state generation, mutate the fixed recovery ring, or initiate shutdown; safe reads
remain bounded, and a concurrent mutator receives `maintenance_transition_busy`. Linux deployment
runs it with `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`; a process-level test also
proves that connector construction is unreachable.
<!-- maintenance-operation-registry:end -->

Bootstrap is eligible only when no valid `active-state` pointer or previously committed bootstrap
exists and no finalized state generation exists except one checksummed pending-bootstrap generation
matching the same command digest. The fixed owner root may otherwise contain exactly the owner lock, a
valid fixed-root control journal and recovery ring (including pending or active pre-bootstrap keys), and
reclaimable staging/pointer-temp files for that command. Any unrelated file, symlink, transition, or generation
fails closed and is never overwritten as “uninitialized.”
Under the A-14.3 protocol bootstrap atomically creates schema, service-state keys, first stable
operator, the UID-0 peer mapping, and initial operational configuration. It creates no recovery key or
API key and returns a secret-free command result. A retry before pointer commit resumes or recreates
only its own pending generation; a crash or response loss after pointer commit is answered by the
command record in the selected database. The operator then uses `recovery_key.generate` and
`api_key.issue` as distinct paired operations if desired. Restore is A-14. Starting either mode is the
unavoidable CLI-only lifecycle operation; everything after listener availability uses its API.

## A-14. Backup and restore

### A-14.1. Backup artifact and job model

Only one backup job runs at once. `POST /v1/admin/backups` creates a generated job ID; it never accepts
a server filesystem destination. A job has `queued`, `running`, `complete`, `failed`, or `cancelled`
external state and a bounded retention deadline. Its internal publication phase is exactly `building`,
`artifact_staged`, `complete`, or `removing`; the filesystem's verified final-name presence is the
recoverable published prefix between `artifact_staged` and `complete`, not an unjournaled success. One
`backup_jobs` row owns one generated temporary basename, one generated final basename, expected
digest/size, the comparison-evidence pin, and a validated-safe-UTC execution deadline with all checked
component maxima/margins and same-boot monotonic mirror metadata. The execution deadline is distinct
from artifact retention and `nonempty_restore_supported_until`. The job-creation FULL transaction
persists those immutable deadline carriers and acquires a conservative
running pin at the then-current comparison anchor before the first online-copy step; prefix compaction
treats every nonterminal job pin as an anchor barrier. Both basenames use a closed service-generated grammar in
the private backup directory; no caller value or path participates. The download operation streams
only a `complete` artifact, whose final file is reopened no-follow and rechecked against the row. The
client CLI chooses and safely creates its local destination. Creation fails before staging when the
fixed-root ring does not have exactly one active escrow-acknowledged recovery generation; a
`pending_escrow` or retained predecessor is never selected implicitly.

The `.mrb` artifact is a path-free framed container, not tar/zip. It contains:

1. fixed magic, format version, and checked 64-bit section lengths;
2. canonical JSON manifest;
3. a SQLite backup image;
4. a canonical exact-reference-closure key section that, as a multiset, equals exactly the set of
   `MacKeyRef` values derived by walking every row class the image requires: `ApiKeyVerifyV1` keys for all
   retained or suspended `api_keys` rows; `LookupV1`/`FingerprintV1` keys for every live or retained
   idempotency row and `CommandLookupV1`/`CommandSemanticFingerprintV1`/`CommandPhaseFingerprintV1` keys
   for every live or retained command row; `ReplayLookupV1`/`ReplayFingerprintV1` keys for every retained
   replay row; `RetryJitterV1` keys for every A-11.3 `JitterKeyDependency(ref)`, including every
   `retry_jitter_unavailable` row and upgrade-era row; `ArtifactInternalAuthV1` keys;
   and `PortableReservationV1` keys referenced by every unexpired/null fixed-root reservation. Missing,
   extra, duplicated, wrong-purpose, unparsable-id, or unreferenced entries fail artifact
   self-verification and restore before any state selection. Each entry is keyed by `MacKeyRef`, occurs
   exactly once, and is encrypted/authenticated with XChaCha20-Poly1305 under an HKDF-SHA-256 key derived
   from the separately escrowed recovery-key generation and fresh 192-bit nonce. Allocator metadata
   independently carries only the artifact's selected-origin purpose-local high-waters; retained or
   imported keys from other origins never raise those values; and
5. a final SHA-256 digest plus domain-separated HMAC over framing/manifest/ciphertext using another key
   derived from the same recovery generation.

The manifest records format/schema versions, compatible binary range, source instance ID, immutable
lineage ID, creation time, SQLite transaction-sequence watermark read from the completed image,
connector/config/key generations, section hashes/sizes, purge-tombstone watermark plus canonical
tombstone count/digest, history epoch plus comparison batch head sequence/digest, and provider-safe
counts by message state. It also freezes
`nonempty_restore_supported_until` from the configured support window; that deadline is authenticated by
the artifact and repeated in local provenance. The manifest
contains no payload, destination, raw caller identifier, provider credential, endpoint, or secret; it
names only the public recovery-key generation required for verification/decrypt.
The artifact as a whole is nevertheless classified sensitive because its database and state keys can
contain or protect sensitive evidence. It is created mode `0600`, served only on local operator UDS,
never logged by path, and is not retained beyond the configured bounded window.

Provider credentials, recovery-key bytes, the fixed control journal and its host-local integrity key,
bootstrap envelope, and host secret files are not in the artifact. Unknown, unreferenced by an image row
or framing requirement, duplicated, missing, wrong-generation, or wrong-purpose entries make artifact
self-verification and restore fail.
The purpose-separated portable
reservation MAC keys in encrypted section 4 are the sole exception and cannot authenticate the journal
or provider/API credentials. The manifest lists required non-secret provider, recovery-key, and
secret-reference generations so recovery can fail closed or hold work until deployment restores them.
A stolen artifact alone therefore cannot use persisted HMAC fingerprints as a low-entropy payload
oracle.

### A-14.2. Online backup algorithm

The store actor creates a same-filesystem temporary destination with `O_EXCL` and starts SQLite's online
backup API from its own sole read/write source connection. It retains that backup handle and performs a
bounded default 256-page `backup_step` as a critical command, then returns to queued mutation work before
the next step. Because all writes between steps use the same source connection, unrelated-connection
writes cannot repeatedly restart the backup. Those inter-step writes use A-10.1's shared-borrow
`Transaction::new_unchecked(..., Immediate)` path with explicit result-bearing commit/rollback/finish;
RAII is only the panic/unwind backstop. No `&mut self` transaction helper or raw transaction-control
statement is permitted while the handle lives. A rollback failure immediately poisons the source
connection and aborts further actor/backup work; recovery drops both handle and connection, reopens and
revalidates the store, then reconciles the durable backup prefix without extending its deadline. The
algorithm never manually copies a live main database/WAL pair.

The job has a checked page/byte estimate, the immutable durable execution-deadline carriers above, a
cancellation flag, and reserved destination space.
At the maximum first-slice queue/reference profile it must reach a terminal complete/failed/cancelled
state within 10 minutes while sustaining 50 submissions/s; the release evidence records actual bound
and actor latency. A deadline failure is loud and leaves active state unchanged, never an endlessly
running job. Actor weighting keeps outcome/admission bounds while backup advances at least one step per
configured maximum interval.

If a clock anomaly begins after admission, the coordinator freezes its original same-boot monotonic
remainder and authenticated safe-UTC deadline. It starts no further copy, verification, framing, or
publication step and cannot cross the step-3 rename or step-4 completion boundary. Startup may inspect
and remove an owned invalid/stale prefix under the ordinary crash protocol but cannot manufacture a
time-derived terminal or success. Atomic clock settlement re-derives the conservative remainder from
the immutable deadline and authenticated high-water. If positive, the same job resumes from its
reconciled prefix without extending the deadline; if proven elapsed, one FULL failed/cancelled terminal
transaction follows owned-artifact removal and releases the running comparison pin. A still-unprovable
deadline remains held and blocks upgrade quiescence rather than publishing or failing by guessed time.

After SQLite-copy completion the worker opens the copy read-only, verifies database profile, `quick_check`, full
`integrity_check`, foreign keys, migration checksums, the embedded transaction watermark, the exact
history-epoch/boundary path and comparison anchor-to-head sequence/count/ordinal/digest chain, and the
purge-event/tombstone projection. The manifest tombstone count/digest/watermark must equal the copy's
canonical rows; its epoch/head must equal the copy's meta head and the source active-pointer certificate.
That
observed copy watermark—not job start time—defines the RPO. It walks each A-14.1 row class and builds an
independent purpose/generation reference multiset, then requires the canonical encrypted key section to
equal that multiset exactly before and after framing; no broad “current ring” export substitutes for
row-reference closure. It frames/encrypts the artifact and verifies it once through the restore parser.

Publication then follows one exact crash protocol under the store actor and a per-job filesystem
coordinator:

1. fsync the verified mode-`0600` temporary artifact, fsync the private backup directory, and reopen the
   temp no-follow to recheck generated basename, regular-file identity, length, and digest;
2. in one `synchronous=FULL` SQLite transaction, move the job to `artifact_staged` and durably record
   temp/final basenames, digest/size, source instance/lineage, completed-image watermark, base tombstone
   count/digest/watermark, history epoch/comparison head, and support deadline while retaining the
   conservative creation-time pin;
3. rename that exact temp to the absent final basename with Linux `RENAME_NOREPLACE` semantics and fsync
   the backup directory. An existing non-identical target fails closed; there is no overwrite fallback;
4. reopen the final no-follow and reverify identity/length/digest, then use one FULL transaction to
   insert immutable `backup_history`, set the job `complete`, and convert its running comparison pin to
   the provenance dependency through `nonempty_restore_supported_until`.

Only step 4 makes status/manifest/download report completion. The scalar transaction watermark remains
the RPO but is not a continuity proof. Comparison cleanup stays pinned from job creation through step 4,
so no required batch can disappear during copy or off-actor verification; the step-4 transaction
atomically converts that conservative pin to the exact completed provenance dependency.
Provenance and the content-free batch suffix remain through the frozen deadline even when the
downloadable server copy is removed earlier.

Before readiness or any backup list/show/manifest/download/cancel/retention operation, startup scans
only the closed reserved-name grammar and reconciles every nonterminal `backup_jobs` row under the same
actor/coordinator. `artifact_staged` plus a verified temp and absent final resumes at step 3; staged plus
a verified final resumes at step 4 after another parent fsync. Identical temp+final removes the temp and
fsyncs before completion; conflicting, partial, corrupt, missing, symlink, or wrong-identity ownership
fails closed. A `building` partial and a reserved-name file with no owning row are removed no-follow and
parent-fsynced before a terminal failure/orphan-cleanup record. A `complete` row with a missing or
mismatched final artifact is post-commit corruption: readiness degrades, download fails with a stable
artifact-integrity error, and immutable provenance is retained rather than rewritten as a successful
file deletion.

Cancellation and deadline failure claim the same coordinator. A new cancellation request first needs
the ordinary mutator admission proof; during `clock_hold` it returns exact `503 clock_hold` with null
`retry_after_ms` and changes nothing. Only cancellation intent already durable before the anomaly may
continue through the cleanup/terminal prefix below under its retained deadline proof. Before step 3 it
removes the exact temp;
after final rename but before step 4 they remove the exact final. In both cases unlink plus
parent-directory fsync precedes the FULL terminal failed/cancelled transaction and release of the
running pin. Retention removal of a completed download first sets `removing`, unlinks the verified final,
fsyncs the parent, and only then records file absence; it never removes `backup_history` or releases the
comparison-provenance dependency before its support deadline. Startup resumes every `removing` prefix.
The separate storage-safety admission hold closes before backup can consume the full storage peak or
emergency reserve; it never writes the operator-admission row or its complete revision address.

### A-14.3. Restore staging and validation

Restore requires normal mode stopped and maintenance mode holding the state lock. The API streams one
artifact into a newly created bounded staging file while hashing; framing lengths, inactivity, total
bytes, and disk reserve are checked before allocation/write. Before the first byte, the fixed control
journal durably binds command digest, declared length, and encrypted-artifact digest. A crash or handler
failure leaves a partial upload that the in-process/startup coordinator removes and terminalizes as
`input_abandoned`, or a complete digest-verified upload it reuses and finishes without caller input. A
different key/body conflicts only while that reconciliation remains nonterminal; after safe
terminalization another key may start immediately. The parser has no paths, symlinks, or
archive extraction. It requires the manifest's recovery-key generation from the separately escrowed
ring, verifies digest/HMAC/AEAD before accepting decrypted state keys, and verifies schema/binary range,
state-key consistency, SQLite integrity/foreign keys, manifest-to-meta epoch/head equality, the entire
staged epoch/boundary and anchor-to-head comparison chain, purge-event/tombstone equality, and
configuration compatibility before touching active
state. A missing recovery generation fails with its safe public ID and no partial activation.
Configuration compatibility validates every restored secret-reference name against one atomic
metadata-catalog generation. An absent name fails before generation finalization with a bounded
root-only diagnostic; a cataloged name whose value is not installed is valid and later holds only its
connector. The catalog basename is reopened through the metadata-directory descriptor while the shared
owner lock is held and its inode/generation/digest is rechecked before pointer commit, so a blank host
must pre-provision names but maintenance never needs secret values and normal recovery status cannot be
stranded by an unknown-name startup failure.
The configured restore byte cap must cover the maximum valid DB + encrypted key section + framing
produced by the configured queue/backup profile; validation rejects a system that can create an
artifact its own restore path cannot stage, including simultaneous rollback-generation reserve.

If current state exists, maintenance first requires its retained backup-provenance row to match the
artifact digest, source instance, lineage, completed-image watermark, authenticated support deadline,
and authenticated history epoch plus comparison batch head sequence/digest exactly and to prove the snapshot is an
ancestor of that state. Current validated UTC must be before the half-open support deadline, and the
live retained anchor must not be later than the artifact batch head. It first verifies the source active-
pointer certificate, requires the live chain to terminate in that selected epoch, then verifies every
typed epoch transition and contiguous batch/header/event ordinal/count/digest from artifact head+1
through the live meta head before reading
the ordered events, recording safe counts and generated IDs for commands newer than the snapshot, and
identifying snapshot work whose later
non-terminal/effect/ambiguity/terminal events can repeat an effect and identify later payload purges. It
reads the authenticated base tombstone set/count/digest from the artifact image, derives the exact
post-snapshot projection from verified events, rejects any overlap mismatch, and requires the union to
equal current rows. Any missing, extra, changed, or wrong-epoch base or suffix row fails before the union
is applied to staged state. Failure to prove continuous coverage is
an unsupported-restore conflict before generation finalization; it can never produce a shorter report.
A sibling, foreign-instance, expired, forged, missing-provenance, or coverage-gapped artifact is
rejected before activation in v1; no acknowledgement overrides this boundary. If no current state
exists, `nonempty_restore_supported_until` is not an eligibility gate: the same cryptographically and
structurally valid artifact remains restorable after that deadline, but the report marks post-watermark comparison unavailable, treats every
snapshot payload as potentially resurrected, and does not claim zero loss or duplicate risk. The
restored database receives a new runtime instance ID while preserving the lineage and source provenance
chain. Before any pointer mutation it decrypts each portable reservation key generation, validates
exact references from every unexpired/null fixed-root command row, and computes the current restore
command under those generations. A match aborts as `command_namespace_changed`; no foreign result is
trusted. Unexpired `operation_commands` rows retain their source runtime, so reused generic or portable
fixed-root command digests collide instead of authorizing a restored result or fresh effect.

For a proven nonempty restore, the typed staged mutation copies the verified content-free comparison
epoch/batch suffix, retains the artifact base tombstones, derives the post-watermark suffix tombstones,
and copies unexpired/null portable fixed-command reservation rows plus
their MAC generations from current state; it also retains the artifact and new-host generations needed
by restored/current commands. For a proven nonempty restore, the staged MAC key set is the union of the artifact key set and the
current-state keys required by copied portable reservations. Every restore staged-key set, whether
proven-nonempty or blank-state, MUST pass one common merge algorithm. The algorithm MUST first apply
R3-INV-108 to every candidate row: equal `MacKeyRef` values with unequal key bytes MUST return
`409 mac_key_identity_conflict` before capacity evaluation. It MUST then deduplicate byte-identical equal
refs, group the union by `MacPurpose`, and require every group to contain at most
`MAX_RETAINED_MAC_KEYS_PER_PURPOSE`; an over-bound group MUST return stable
`409 mac_key_ring_full`. Both failures necessarily follow the durable command/input intent and any
applicable same-intent branch-serial burn because the candidate rows require artifact authentication and
decryption; both MUST occur before destination key-file staging, generation finalization, pointer
selection, or any selected-state mutation. The restored branch allocates a new incarnation whose purpose
high-waters start at zero for future keys. Sibling branches MUST carry distinct authenticated
`OriginIncarnation`s, while serials MUST remain monotone and never be reused within each
`(OriginIncarnation, MacPurpose)`; therefore equal refs imply byte-identical keys or
`mac_key_identity_conflict`, never a silent overwrite.
It inserts the exact restored-artifact provenance row and advances the
restored transaction and comparison batch sequences beyond the current heads, installs the intent-bound
new structured history epoch whose parent is the verified selected source epoch/head, and records its typed digest-
chained restore-boundary batch. It does not copy current backup rows created after the artifact watermark:
those artifacts belong to the abandoned descendant branch and are not ancestors of the restored state.
Ancestor provenance/events already present in the snapshot remain, so the restored artifact and its
older ancestors keep continuous support without making a sibling artifact eligible. For blank-state
restore there is no current comparison suffix or local provenance to import. A new epoch boundary names
the authenticated artifact head with `comparison_unavailable`; the complete artifact key set, including
every artifact reservation generation, plus the new-host current restore reservation generation form the
blank restore's complete staged MAC key set and MUST pass the common identity, deduplication, and per-
purpose capacity algorithm above. Thus sixteen distinct artifact `PortableReservationV1` generations
plus one distinct new-host generation MUST return
`409 mac_key_ring_full` at the common pre-key-file/pre-finalization/pre-selection boundary, and comparison
unavailable remains the only honest report claim.

Before activation it materializes one immutable restore-safety report with canonical summary, tagged
detail entries ordered by `(section, generated_id)`, per-section totals, and SHA-256 digest. The report
is retained through the restore hold/evidence horizon and served only as bounded
`json.restore_report_page.v1` pages under A-07.7; no truncation or one-response assumption is permitted.
Its digest excludes the separately stored live status overlay, so expiry/status changes during the hold
cannot invalidate the operator's safety acknowledgement.

The staged database invalidates every lease/fence authority, converts recoverable delivery work to the
appropriate queued/ambiguous representation, suspends every restored API key, peer mapping, and
provider grant, disables TCP through a restore quarantine, and sets global admission/effect
`restore_hold`. It creates a new generated recovery principal and enabled local operator peer mapping
bound to authenticated maintenance UID 0 with operator scope/ceiling, satisfying A-05's irreducible
path before selection. The intent-bound allocated restore history epoch is also the exact 32-byte
`resource_incarnation`. After quarantine truth is final, the same typed staged mutation writes that
incarnation into admission and every surviving principal/grant collection, resets each guarded
generation to `(0,1)`, and clears every guarded receipt. It replaces artifact-era operator admission
with a fresh durable `closed` row whose actor is that recovery principal and whose reason is `restore`;
neither descendant admission intent nor a blank-host default can make that row open. No restored
credential, artifact-era receipt, or abandoned-branch numeric generation can inspect, address, or
resume authority in the instance.
It stores the canonical security/RPO/duplicate/resurrection report plus digest.

Bootstrap, restore, configuration activation, service-state-key rotation/retirement, migration, and
rollback share one copy-on-generation protocol under the fixed owner root:

0. acquire the transition gate and persist/fsync the A-13.2 control-journal intent before creating or
   changing any staging, generation, key, pointer, or deletion target. For the exact allocator registry,
   this same authenticated image advances/burns the fixed-root branch serial and fixes the namespace/
   serial-derived target: bootstrap allocates the initial epoch, restore/rollback allocate a new branch
   epoch with the exact parent head, and continuation operations preserve the selected epoch without an
   allocator write. Same-intent recovery reuses the bound target;
1. create a unique mode-`0700` staging generation and populate its SQLite database plus exact state-key
   files. Restore/bootstrap build verified new state. Configuration, state-key, and migration changes
   clone the selected stopped generation. Rollback clones the recorded sealed pre-migration source
   generation into a *new* generation; it never repoints to or edits that source and never clones the
   selected migrated database as its rollback payload;
2. for every clone, open the source SQLite database under the owner lock/transition gate, verify its
   durability profile and integrity, verify its HMAC pointer certificate plus complete epoch/comparison
   chain and tombstone projection, and read its transaction-sequence watermark. Use SQLite's online
   backup API from that connection into a newly created destination—never a raw main-file/WAL copy.
   With no concurrent source writer, run backup to completion, verify destination watermark equals the
   captured source watermark *before* typed mutation, then run `quick_check`, full `integrity_check`,
   foreign keys, and schema checks. Copy referenced state-key files with no-follow/open-first reads,
   exclusive destination creation, checked lengths/digests, file fsync, and exact DB-reference equality;
3. apply only the operation's typed staged mutation. It carries into the target the maximum safe-time
   high-water present in the authenticated target image, fixed-root journal, and selected source/current
   state named by the transition; a blank-host restore has only its artifact and fixed-root inputs and
   does not invent an absent off-host proof. Failure to authenticate a required marker fails the
   transition before selection. Any physically retained caller row at or below that carried maximum is
   logically absent before pointer selection, restore status, or resume and cannot disclose or reserve
   authority through a reconciliation crash prefix. Canonical operational configuration lives in
   SQLite, not a second file. Bootstrap installs its initial history epoch as every guarded-resource
   incarnation at generation one. Restore and rollback install their newly allocated target epoch as every
   guarded-resource incarnation, reset generations to one, and clear receipts after typed target truth
   is complete; every continuation operation preserves all three components byte-for-byte.
   Checkpoint/close destination SQLite and fsync every created file plus the
   staging directory. Migration additionally freezes its exact typed transaction/comparison delta and
   mirrors only the complete authenticated A-10.7 lifecycle projection before finalization, recording
   its exact `migration_lifecycle_commitment`; activation extends the later checkpoint/tail transcript
   rather than assuming the head stayed fixed. Rollback applies the complete validated
   prepare-to-rollback projection to its fresh
   source clone;
4. rename staging within the canonical `generations` directory to `g-` followed by its authenticated final
   generation rendered as exactly sixteen lowercase hexadecimal digits, then fsync that directory. This
   finalizes a complete generation identity but does not activate it;
5. derive one temporary basename from the valid certificate transition ID:
   `active-state.tmp.` followed by lowercase hexadecimal `SHA-256(ASCII("msgriver/active-state-pointer-temp/v1") || UTF8(transition_id))`.
   It is a fixed-width ASCII basename, never a path component. Create it only
   relative to the fixed owner root with `O_EXCL|O_NOFOLLOW`, mode `0600`, and
   write the complete authenticated pointer certificate before file fsync. If
   that name already exists, retry may continue only by reopening the exact
   relative name with no-follow semantics, requiring a regular current-euid
   mode-`0600` single-link file of the exact certificate length, byte-comparing
   its entire contents with the newly encoded certificate, and fsyncing that
   verified file. Every differing object or failed check is closed; the helper
   neither unlinks nor truncates it. Different orphan pointer temporary files
   remain inert for authenticated coordinator recovery;
6. the sole private active-state-update capability resolves the fixed root exactly once into a
   no-follow `O_PATH` identity reference, validates its current-euid mode-`0700` directory identity,
   opens/checks `msgriver.lock` and one `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` operational descriptor
   relative only to that reference, and retains the lock/reference/descriptor together. It never performs a
   later path-based lock or active-state operation. The caller supplies either `replace_existing` or
   `require_absent` through that capability. For `require_absent`, use Linux `renameat2(RENAME_NOREPLACE)`
   relative to its operational descriptor and fail closed when unavailable or unsuccessful, with no
   check-then-rename fallback. For `replace_existing`, while it retains the state-owner lock, first require
   `active-state` to be a no-follow regular current-euid mode-`0600` single-link leaf, then atomically replace
   it. Missing/invalid destinations and every failed mode check are closed and never select the other mode.
   After the chosen rename, fsync the same operational descriptor. `PointerRenamed` becomes only a private
   lifetime-bound rename-durability observation borrowing that retained capability; it is not activation,
   selection, journal authority, or a response. A drop after rename releases no authority beyond the durable
   authenticated prefix, which later locked recovery determines from its existing durable evidence; no unlocked
   actor cleans, selects, or terminalizes it. Caller-owned step 7 must still reopen and verify before a terminal
   response;
7. while the same caller retains step 6's lock/reference/operational-root capability, its
   `PointerRenamed` observation carries only an opaque borrowed view of that already-retained operational
   root and may enter exactly one private non-Clone pre-terminal coordinator together with the authenticated
   pointer. No supplied generation name, descriptor, root, directory scan or pointer reread can create the
   coordinator. It alone derives one private non-Clone `PointerNamedGeneration` handle from the pointer's
   nonzero final generation, bound to that retained root; it carries the pointer certificate digest only into
   an exact selected SQLite-meta equality obligation. It alone derives `g-` plus the authenticated final
   generation's sixteen lowercase hexadecimal digits, opens the current-euid mode-`0700` `generations` child
   relative to its retained operational descriptor with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and
   descriptor-local `fstat`, then opens only that derived candidate relative to the verified child with the
   same flags and checks. It owns that candidate descriptor privately without duplication or exposure; the
   handle remains coordinator-borrowed. This proves only a candidate reopen, never completion or selection.
   Only the coordinator-borrowed candidate may open `state.sqlite3` relative to itself with `O_RDONLY`, `O_NOFOLLOW`, and `O_CLOEXEC`; fstat requires a current-euid-owned mode-`0600` single-link regular file. Its same-descriptor private sealed-image observation establishes checkpoint/close after the pointer mirror write and that WAL/SHM cannot alter the read-only view. The exact singleton-meta equality fact is private and nonterminal, never selection or completeness. The future internal sealing adapter is [PENDENTE: Task0146/0147 pointer-authenticator ownership]; no crate, FFI/VFS implementation, sealing RED, selected-meta comparison, or root-side substitute is authorized until its source-first reentry condition closes. A private nonterminal comparison fact rejects supplied
   digests/booleans and grants no
   selection, journal, cleanup or response authority. The coordinator then forms one indivisible
   same-transition/same-target evidence bundle: authenticated pointer transition, final generation,
   lineage, epoch, origin and certificate digest; the selected SQLite meta certificate-digest comparison;
   schema, canonical configuration, comparison/tombstone projection and state-key consistency; and the
   durable fixed-root journal command/body/monotonic phase plus selected SQLite command mirror. It rejects
   supplied descriptors, names, comparisons and phases, and any absent or disagreeing fact. Only the
   complete bundle may yield the private nonterminal `PostRenameValidated` receipt. A later boundary owns
   terminal-journal publication, any exact SQLite mirror write, response-loss handling and the committed
   API response. Every completed barrier advances and fsyncs the monotonic journal phase. Recovery may
   infer the pointer barrier only when its HMAC-authenticated transition ID/epoch matches the journal
   target, and must repeat this complete aggregate validation before it advances a missing phase; a
   pointer reread, directory-name guess or journal record alone grants no selection, cleanup, terminal
   result or response.

With an existing pointer, every prefix before step 6 selects the complete old generation and every
prefix after it selects the complete new one—never no pointer or a mixed generation. The fixed-root
journal lets only the same caller command/body resume a no-old-pointer window, while its key-independent
coordinator may finish a complete durable prefix or terminalize/remove a safely reversible missing-input
prefix under A-13.2. Orphan staging and pointer-temp files are inert; an unselected finalized generation is never
guessed active. Once a generation becomes inactive it is sealed. Old and new generations remain until
the maintenance `state-generation delete` API/CLI operation verifies inactive status, transition/upgrade/backup/
recovery dependencies, and explicit destructive acknowledgement. If unrelated final generations exist
without one valid pointer, startup and bootstrap fail closed. Every file/directory create, rename,
fsync, reopen, and response-loss boundary is a crash test for every operation using this protocol.

For migration, step 6 selects the complete held target generation but does not end A-10.7's
rollback-eligible read-only phase; “pointer activation” in this protocol is distinct from the later
cataloged `upgrade.activate` transaction. That transaction clears the upgrade hold only after exact
target/certificate/delta verification. Rollback runs this protocol again against a fresh clone of the
sealed prepared source and may select it only after the same lifecycle-mirror and certificate checks.

`state_generation.delete` carries a caller command key, acquires that same transition gate before
resolving the active pointer, and keeps it through dependency validation, removal, parent fsync, and
terminal result publication. It
rejects the active generation, any source/target named by a nonterminal journal entry, every permitted
rollback source, every generation named by an unresolved `upgrade_diverged` record, and every retained
backup/recovery dependency. It first atomically renames the
validated no-symlink target to `.deleting.<command_digest>` and fsyncs the generations directory; only
then does it remove the exact
tombstoned tree without following links and fsync the parent again. Crash recovery resumes only that
journaled command/body/generation tombstone; same-key retry returns its phase/result and a different
key conflicts while it is nonterminal. Activation therefore cannot select a directory concurrently
observed as deletable.

### A-14.4. Held activation and resume

Maintenance exits after successful restore. Normal mode starts against the restored database but
remains unready for effects and serves status plus `GET /v1/admin/restores/current`; the CLI `restore
report` invokes its bounded page operation without reading state. Each page repeats the immutable
report digest, watermark, section totals, page ordinal, and next cursor. TCP remains disabled. Through the fresh recovery
peer only, the operator can inspect audit/report and deliberately create principals, mappings, grants,
and new API keys. `POST /v1/admin/restores/current/resume` must contain
the exact report digest and watermark plus explicit acknowledgements for RPO, possible duplicate
effects, resurrected payload, unresolved tombstones, credential quarantine, and TCP policy. The actor
must be the fresh local recovery principal; restored principals/keys cannot authorize it. One
transaction audits the actor, conditionally clears TCP quarantine only when replacement authorization
exists, and clears the restore admission/effect safety holds; it does not alter A-14.3's durable
operator-closed row. Scheduler wake occurs only after commit. A second resume is an idempotent safe
result. New submission stays closed until a separate `admission.set open`. No resume field, startup
flag, config value, restored credential, or restart implicitly opens admission or clears another hold.

`restore_hold` blocks admission and provider effects but does not pause expiry/max-age when the clock
guard considers UTC safe; commands may become terminal while the operator evaluates the report, and
live status counters update monotonically in the separate overlay without changing report pages or
digest. A concurrent `clock_anomaly` hold pauses those time transitions under A-11.5. Resume never
revives an expired command.

## A-15. Observability and diagnostics

### A-15.1. Structured event allowlist

Tracing events are typed constructors with a closed field allowlist: timestamp, level, event code,
generated request/message/attempt/backup ID where permitted, principal/provider internal reference,
state/outcome class, duration bucket, and numeric count. There is no generic `message = %error`, debug
dump, HTTP trace body, SQL bind logging, or provider response logging. Error source chains cross the
telemetry boundary only after mapping to safe codes.

JSON logs go to stderr/journald. Startup can require an available sink; after startup sink failure is
rate-limited to a safe stderr fallback without blocking the store actor. Panic hooks print only build
ID and safe panic location; release service policy disables core dumps. Capturing subscribers in tests
scan every level and failure path with sentinel secrets.

### A-15.2. Metrics and audit

Metrics have a fixed prefix and enum labels only. They cover API/auth result classes, mailbox
occupancy, queue states/age, attempts/outcomes/latency, retries, circuit/hold state, ambiguity and
duplicate risk, dead letters, backup/restore jobs, SQLite commit/checkpoint health, WAL bytes, disk
reserve, and build/schema info. Principal, message, topic, destination, route, error text, endpoint,
credential reference, and provider response never become labels.

Durable `audit_events` record authorization denials, key/principal/grant changes, replay/purge,
config validation, drain/clock acknowledgement, backup/restore/resume, and migrations using generated
references and closed codes. Audit retention is bounded and cannot retain request bodies. The API does
not claim to replace host audit/journal collection in v1. `audit.list` exposes the same bounded,
paginated safe fields over local operator UDS and CLI; there is no hidden SQLite-only audit reader.

### A-15.3. Health and readiness

Health reports only process/mode/build liveness. `msgriver-core::readiness_reason` MUST compute only
the pure exhaustion subset `{generation_exhausted, incarnation_exhausted}` and its mutual precedence from
the supplied branch high-water and guarded generations; it MUST perform no I/O and MUST render no
presentation text. The application readiness coordinator in `layer:server` MUST assemble the complete
closed `ReasonSet` from that core subset plus explicitly supplied persisted store availability, migration
compatibility, restore and clock holds, active purpose-09 availability, retry-jitter-hold presence, control-reserve and storage-safety state, per-purpose MAC serial
high-waters, codec availability, and the maintenance-transition snapshot; it MUST perform no hidden I/O.
The complete `ReasonSet` MUST be the following closed enumeration — store unavailable, migration
mismatch, restore hold, clock hold, retry jitter unavailable, control reserve exhausted, storage safety breach, or
`transition_in_progress` while a maintenance mutator holds the transition gate; it MUST contain exact
`generation_exhausted` when any live guarded resource is at `u64::MAX`; it MUST contain exact
`incarnation_exhausted` when the fixed-root branch-serial high-water is at `u64::MAX`; it MUST contain
`mac_key_serial_exhausted` when one `(origin, purpose)` MAC serial has reached `u64::MAX`; and it MUST
contain `idempotency_codec_unavailable` when a live idempotency row references a canonicalization version
or schema codec unavailable in this binary. It MUST contain `retry_jitter_unavailable` while the active
purpose-09 `RetryJitterV1` key is unavailable or corrupt, or while any retained non-terminal row has that
hold reason; this degrades readiness without exposing the row, key identity, or
raw provider outcome. A readiness reason MUST NOT expose a resource, actor,
incarnation, receipt, serial, key identity, or generation value.

The CLI is rendered by `layer:client` from the `ReasonSet`, using exactly these fixed sentences: for
generation exhaustion,
`Guarded resource generation exhausted; select a supported fresh branch or migrate the representation.`;
for incarnation exhaustion,
`Owner-root branch serial exhausted; use a new independently keyed blank root for authenticated disaster restore.`;
for MAC serial exhaustion,
`MAC key serial exhausted; perform a supported branch transition to allocate a fresh key origin.`; and
for an unavailable idempotency codec,
`Idempotency evidence references an unavailable canonicalizer or schema codec; restore the missing codec or rebuild evidence.`.
When generation and incarnation exhaustion are both present, the CLI renders the incarnation sentence as
the sole recovery instruction and suppresses the generation-only fresh-branch guidance; core computes
that precedence, the client only renders it. Incarnation exhaustion does not make otherwise permitted
nonallocating operations unavailable, and neither does MAC serial exhaustion, which is not terminal for
the owner root.

The served readiness JSON and metrics are owned by `layer:server`. JSON retains only the stable closed
reason set, and metrics map them only to the bounded low-cardinality `msgriver_readiness{reason="…"}`
series over exactly those closed reasons (`generation_exhausted`, `incarnation_exhausted`,
`mac_key_serial_exhausted`, `idempotency_codec_unavailable`, `retry_jitter_unavailable`, `transition_in_progress`, and the
operational holds above). A provider
circuit changes catalog availability and metrics but not global readiness for durable admission unless
store/outcome safety is at risk. Only the versioned system operations power
CLI and deployment probes. Systemd `READY=1`/watchdog is a local process-manager signal, not an HTTP
alias or authorization bypass. Caddy exposes no local-admin route and never creates an unauthenticated
TCP exception.

Maintenance readiness is served from a bounded atomic snapshot without acquiring the exclusive
transition gate. While a mutator holds that gate it is unready with reason
`transition_in_progress` plus only the safe operation ID and monotonic journal phase; it never exposes
the command/request digest or generation path. Health remains live, so deployment polling cannot
deadlock behind the operation it is observing.

## A-16. Linux packaging and Sol deployment

### A-16.1. Release layout

The release artifact contains the static-linked-as-practical Linux binary, sample config, systemd
units, shell completion, license/DCO/security documents, checksum manifest, SBOM, and provenance. Sol
installs immutable releases at `/srv/msgriver/releases/<git-sha>/` and atomically points
`/srv/msgriver/current` to one release. Mutable state/backups live below `/srv/msgriver/data/` and
`/srv/msgriver/backups/`; only the minimal bootstrap envelope, root-owned metadata-only secret-reference
catalog, and provider secret sources live in `/etc/msgriver/`. Operational configuration is API-managed
state. Release and mutable trees never overlap.

The dedicated `msgriver` account has no login shell and no membership that can read Obliance or other
application secrets. `msgriver-clients` gates main-socket reachability only. The minimal bootstrap
envelope is root-owned; provider secret material is `root:msgriver` mode `0640`; state, key rings, and
backups are service-owner mode `0600` beneath non-traversable directories. The maintenance socket alone
is root-owned mode `0600` so only UID 0 can connect, even though systemd passes its listening descriptor
to the non-root service.

### A-16.2. systemd boundary

Systemd socket units create and pass the primary UDS with explicit `SocketUser=msgriver`,
`SocketGroup=msgriver-clients`, `SocketMode=0660`; the mutually exclusive maintenance socket is
root-owned mode `0600`. The service never relies on its `UMask=0077` to create a group-writable socket.

The normal service unit uses `Type=notify`, explicit executable/bootstrap paths, restart backoff, bounded stop,
`UMask=0077`, `LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`, `PrivateDevices=yes`, kernel/control-group/personality/namespace protections,
`MemoryDenyWriteExecute=yes`, a syscall allowlist, and explicit read/write paths. On the ntfy-only Sol
deployment, IP policy allows loopback only; the portable sample does not pretend systemd hostname
filtering is an application SSRF boundary.

The daemon adopts only the named pre-opened descriptors, sends `READY=1`, and services systemd watchdog
without a second probe listener. The maintenance unit conflicts with and is ordered after stopping the
normal unit, runs the same binary in maintenance mode, enables `PrivateNetwork=yes`, and permits only
`AF_UNIX`. Both modes receive the same pre-opened, read-only, metadata-only directory descriptor and,
after taking the owner lock, open the fixed `SecretReferenceCatalog` basename relative to it; only
normal mode receives descriptors for provider secret values. Host
provisioning atomically replaces and parent-fsyncs that root-owned catalog before opening it with
no-follow checks and a strict size bound. Provisioning must first acquire the daemon's fixed
state-owner lock, so replacement cannot overlap a running normal or maintenance process. Maintenance
therefore can validate names, kinds,
generations, and catalog digests without gaining a secret-value or filesystem-discovery oracle.
Neither service process runs as root. Directory creation/ownership is an idempotent packaging step,
not daemon self-escalation.

Linux performs supported catalog/credential publication through a root-only oneshot provision unit
that `Conflicts=` with both service modes and is ordered before their next start; systemd therefore
cannot open one descriptor generation while the provisioner publishes another. The portable launch
adapter must provide equivalent serialization with the same owner lock. Direct concurrent mutation of
the files is unsupported root tampering, not a runtime credential-rotation path.

### A-16.3. Remote API and real proof

Local UDS proof precedes TCP. Sol then enables `127.0.0.1:8098`; every request still requires an API
key. Caddy may publish `msgriver.vpn.saboia.ai` only on the VPN-bound trusted TLS policy and proxies no
probe/metrics/admin-local routes. Its MsgRiver access log is disabled or structurally redacts request
paths/query strings as defense in depth and always removes authorization headers; generated resource
IDs are non-secret but caller identifiers and future query values are not. MsgRiver
does not trust forwarded identity headers. The first live
proof submits a unique harmless message through the authenticated public client route to the
operator-fixed local ntfy registration, observes `provider_accepted`, and records only safe IDs and
outcome evidence.

### A-16.4. Upgrade, rollback, and host backup

Deployment runs clean artifact verification, API-backed config validation, admission close, truthful
drain, consistent MsgRiver backup, `upgrade.prepare` bound to that completed backup, service stop,
release symlink switch, maintenance migration when needed, new binary held startup/readiness, local
smoke, and `upgrade.activate`. Prepare still performs and durably proves its own post-backup
zero-invocation quiescence before creating rollback eligibility. The switched successor must support
the plan-bound fixed-root journal format, framing, MAC-key format, and per-role codec versions or fail
held before any role conversion; format migration cannot occur inside an open rollback-eligible phase.
Pre-activation rollback
uses the paired maintenance operation plus release symlink and only when A-10.7's exact generation,
transaction/comparison-head, lifecycle-ledger, and certificate guards pass. Held smoke is read-only;
deployment tooling treats `upgrade_activation_pending` as the expected response for every prohibited
mutator and cannot bypass the daemon through SQLite or pointer edits. Clock settlement and shutdown
lifecycle evidence are journal-authoritative and re-mirrored from the exact HMAC checkpoint/tail
transcript projection into either
selected result. An unresolved `upgrade_diverged` record stops deployment for explicit exact-digest
forward repair; tooling never clears it or deletes an involved generation. It never
starts an older binary against unsupported schema or restores a snapshot after post-watermark work.
After activation, rollback means running a compatible binary against current state or forward repair,
never erasing accepted work.

Sol host backup includes the bootstrap envelope, configuration references, SOPS source, consistent
`.mrb` artifacts, and release metadata under retention distinct from live artifact download retention.
Recovery keys are escrowed outside that artifact/host-backup trust domain; the fixed control journal is
not required to decrypt a completed artifact on a blank host. Host tooling never filesystem-copies the
active SQLite main file or raw service-state keys as a substitute for the backup API. Restore is
rehearsed into an isolated state directory with provider egress disabled before the release claim.

## A-17. Test-first verification and quality gates

### A-17.1. Frozen RED suite

Production behavior begins only after one reviewable commit contains the complete compiling test
harness and intentionally failing assertions/stubs. That commit records every failure and is frozen;
implementation agents may not weaken, skip, delete, rename away, or conditionally bypass a test. A
specification defect requires a written adjudication, lens review proportional to risk, a separate
test-change commit, and a new RED evidence record before implementation continues.

The RED suite contains:

- core unit/property tests for grammars, checked time/math, canonicalization, fingerprint/key domains,
  retry jitter, state transitions, stickiness, and fence arbitration;
- SQLite transaction/concurrency/model tests for every invariant, exact half-open boundary, quota,
  scheduling, crash point, migration checksum, pragma, query plan, backup, and restore swap;
- API protocol tests for codecs, duplicate/unknown fields, bounds, auth matrix, uniform not-found,
  pagination, one-time secrets, streaming, and every stable error;
- generated API/CLI parity tests for every descriptor, including independent frozen-catalog equality,
  local-mode rejection, and proof that CLI code/open syscalls never access SQLite, state generations,
  operational config, or key rings;
- driver contract tests with a deterministic in-memory fake and a loopback ntfy peer asserting exact
  bytes, failure classification, redirect/proxy/TLS/body bounds, and ambiguity;
- process tests for lock ownership, signal/crash recovery, startup ordering, maintenance isolation,
  clock/storage holds, graceful shutdown, and delivery-held restore;
- redaction and hostile-input tests across logs, metrics, errors, argv, environment policy, HTTP,
  SQLite after purge, artifacts, and panic paths; and
- one named automated test or evidence recipe for every `AC-*` in product P-17, with AC-025 kept as an
  opt-in live Sol proof rather than part of hermetic CI. The gate fails when the product adds an AC ID
  without a traceability record.

The separately DCO-preserved `specs/release-identity.toml` v1 manifest contains exactly two closed
entries, for `specs/product.md` and `specs/architecture.md`, with each declared version, canonicalization
identifier, and complete SHA-256. Canonicalization decodes strict UTF-8, maps CRLF and lone CR to LF,
and requires exactly one terminal LF; every other byte remains significant, including blank lines,
indentation, and trailing horizontal whitespace. The checker rejects unknown/missing/duplicate keys or
entries, wrong paths/versions/canonicalization, and either digest mismatch before claiming release
identity. The specification and mutation RED commit precedes the manifest commit, which precedes the
checker implementation commit. A coordinated change to specification, manifest, and checker remains a
review-governed maintainer action and is never described as semantic proof from SHA-256.

Before compiling tests, deterministic spec/catalog lint rejects duplicate definition identifiers
(`PR-*`, `AC-*`, `A-*`, or `INV-*`), duplicate operation IDs, duplicate method/path pairs, duplicate
CLI paths, missing/unknown top-level catalog fields, non-exact scalar types/values, document/catalog
version-link drift, unknown authorization/idempotency/risk/codec values,
malformed codec names, divergence from the independent 70-operation
method/path/CLI/request-codec/response-codec surface manifest, divergence from the independent
authorization/binding/idempotency/risk manifest, divergence from the independent fixed-root operation
set, a missing/wrong one-time mode, and any such mutator not classified as `command_key` or
`one_time_secret` except the exact two-operation `addressed_state` registry. Implementation-time generated-set tests reject a catalog codec with no exact typed
implementation. The identifier lint recognizes canonical definition lists/headings across both
documents, rejects bold, bullet, numbered, table, blockquote, heading, or cross-document disguised
definitions, and compares their exact independent ID manifests rather than relying on counts or
incidental references in prose/evidence. It also requires exactly one pair each of maintenance,
upgrade-lifecycle, addressed-state, generation-guarded, and incarnation-allocator registry markers in
start-before-end order, the exact
`23-operation`, `3-record`, and `2-operation` count claims, and equality of their prose IDs to
independent frozen sets. The mutation harness reaches
the same aggregate validation path as the executable for missing/version-link cases, structurally
parses the initial two-column `Field`/`Value` metadata table
under flexible GFM whitespace, requires the exact metadata field order and one occurrence of every
version/product-contract field, and compares the complete normalized product-contract value rather than
a suffix. Canonical PR/AC/INV definitions require their closing bold delimiter. A rejected catalog or
document produces a bounded checker error rather than traceback. Raw document and complete-line caps
run before entity decoding; therefore an overlong line containing a bidi control has the line-cap
reason. Input within those caps rejects the Unicode `Bidi_Control` property after HTML-entity decoding
and before fence classification or any render/table pass. Every complete source line is checked against
the 8,192-character cap. One bounded fence
tokenizer then drives all fenced-line provenance. It recognizes top-level, blockquote, list, and mixed-container continuations,
limits ordered list markers to nine digits, ends masking when the exact container ends, and rejects a
backtick anywhere in a backtick fence's info string. A blank continues a non-top-level fence only when
the exact container continuation is present; an unprefixed blank terminates quote/mixed provenance
before a later container re-entry. The complete document is then parsed as one raw-HTML stream of at
most 1,048,576 source characters and 64 modeled open elements. HTML-parser work is no greater than
twice that pass's own masked/rendered input; every subsequent pass is linear in its own bounded input. The
parser appends visible text only to one current run, starts a candidate run at every modeled break or
structural boundary, and requires a close to match the stack top; crossed, incomplete, or unclosed
markup fails closed. Case-folded duplicate attribute names, style/class/id/direction/popover, style
elements, external stylesheet links, unmodeled elements, and context-sensitive visibility elements fail
closed; silently deleting a visual-order control, retaining only one duplicate attribute, or guessing
host rendering is forbidden. Multiline raw tags, comments, declarations, processing instructions, and
hidden subtrees that can cross source-line candidate boundaries also fail closed. Complete benign
single-line comments, declarations, and processing instructions are accepted standalone but cannot
split any linkage label. The pinned CSS-free model omits single-line script/template, `hidden`, and exact `aria-hidden=true` subtrees and accepts
genuinely visible attribute-free HTML. An escaped backtick cannot open a code span in this pass. One
offset-preserving Markdown tokenizer emits separate rendered-byte, raw-HTML-eligibility, and visible-
literal provenance. Only a grammatically complete link/image construct owned by one inline block may
classify its title, destination, or reference label as non-rendered. The visible link/image label
opener, its nesting, and its eventual closing bracket are owned by that same block; before examining
the first byte of every inline-block boundary, the tokenizer clears all pending label state. Soft line
breaks inside one paragraph retain that state. A destination contains no line ending; a reference label
cannot cross its block; and a title may span lines but contains no blank line and remains inside its
original paragraph. Invalid or block-crossing syntax is restored as visible source before normative-ID
classification. Escaped tag delimiters plus fenced/inline code and autolinks
are visible literals but cannot open or close the raw-HTML stack. Valid fenced definition-shaped
examples and metadata-shaped rows are accepted. Restoring an unmatched inline-code delimiter never
unmasks independently proven fenced lines or crosses a blank, container, heading, thematic, fenced, or
HTML-block boundary. For paragraph interruption, only an ordered marker starting at `1` is a boundary;
an already-established list/container continues to accept every valid one-to-nine-digit ordered marker.
Ordinary multiline inline code inside one paragraph remains literal. The frozen inline-code normative-ID and later-table linkage disguises remain
rejected, including a one-line or source-split structural HTML cell; whole-document cell provenance,
not an incidental per-line unclosed-tag failure, supplies that oracle. It then uses NFKC normalization,
enforces an exact 32,768-character normalized rendered-candidate cap, and applies explicit Unicode
default-ignorable plus control/combining-character removal and bounded
forward Markdown scanners. One indexed scan accepts at most 64 structural prefixes without shrinking-
suffix rescans; the inline scanner separately asserts examined work no greater than its input. Exact
fenced and non-fenced 8,192/8,193,
64/65, 1,048,576/1,048,577, and normalized 32,768/32,769 boundaries are exercised through the aggregate
path. The scanner retains link
labels/image alt text while discarding full, collapsed, shortcut, balanced, quoted-title, and angle-
bracket destinations; strips GFM task markers; and evaluates each structural HTML cell independently,
including cells split across source lines.
Nested structural prefixes are stripped before table interpretation. Setext headings,
bare/bullet/blockquote/heading colon forms, structural HTML headings/tables, bare paragraphs, and GFM tables
with either or neither outer pipe are classified. A literal outer-pipe paragraph yielding one rendered
cell is classified as one bounded definition candidate without changing real multi-cell table rules.
One bounded rendered-suffix scan rejects an em-dash/colon definition anywhere after a canonical PR, AC,
INV, A-section, or A-subsection core. Period forms enter only through actual matched rendered delimiter
spans or visible HTML runs, never a raw delimiter token or direct unwrapped suffix, preserving immediate
and later ordinary `AC-001. This ...` prose. Delimiter spans require matched opener/closer roles, equal
width where required, GFM flanking, escape and code/channel ownership, and containment of the candidate
ID. One forward backtick scan pairs only the next equal-width run and skips its complete span, so spans
cannot cross and foreign-width runs within code remain visible literal bytes. Rendering removes only
syntax positions belonging to proven matched spans; unmatched or foreign-width delimiter bytes remain
before leading-ID classification. The scanner recognizes isolated one- or two-tilde
strikethrough per GFM section 6.5 but not runs of three or more. It crosses 24 wrappers plus eight inner-
separator emphasis/visible-HTML/one-tilde forms over all five owners (160), plus four Markdown title/
destination/escape HTML-state boundaries × five owners (20), and period forms over all 25 attribute-
free visible inline HTML elements × five owners plus three
nested/hidden-prefix/inline-code-prefix compositions × five owners (140), in
addition to the 20 plain/modeled-HTML-break cases. A separate matrix crosses ten known/unknown owner IDs,
seven inline link/image destination/reference-label/title forms, and eight blank/heading/list/quote/
thematic/fence/HTML block boundaries (560), proving that invalid inline syntax cannot mask a later
definition. A separate four link/image, nested-label, three-title-delimiter, and reference-label forms
× ten known/unknown owners × eight boundaries matrix opens visible label state in the prior block,
closes it later, and places `<br>ID: Shadow definition.` inside later balanced non-rendered-looking
syntax (320); every case rejects because no label state crosses the boundary. One soft-line multiline
link label, one soft-line multiline image label, and one broken cross-block ordinary-prose label are the
three accepted controls. List-marker padding uses the same raw-offset-preserving four-column tab view
as table ownership: two stale inline-code/label forms × `-\t`, `*\t`, `+\t`, and `1.\t` × ten owners
add 80 rejections. Ordered `2.\t` and `9.\t` remain paragraph continuations in both forms and are
accepted controls. A one- or two-hyphen Setext underline also ends the prior inline block. An
interrupting unordered marker or ordered `1` followed by more than four padding columns still begins a
list, with excess indentation belonging to its first item block; neither form may retain stale inline
state into the next visible line. Two stale states × nine short-Setext/five-space/tab-over-padding forms
× ten owners add 180 rejections. Ordered `2`/`9` over-padding adds eight non-interruption controls, and
four top-level/quoted/nested tab-padded list fences add literal-code acceptance controls for the shared
fence scanner. A recognized GFM table establishes additional inline ownership: header and body
rows are split into independent cells at raw unescaped pipe delimiters before inline code is parsed,
and pending label/image state is cleared at every cell, row, and table exit. Four link/image/nested/
title/reference forms × ten owners × six header/body cell/row and code-pipe transitions add 240
rejections. An ordinary non-table pipe, an escaped table-cell pipe, an incompatible code-pipe
header/delimiter pair, and complete titles within one header or body cell add five controls.
Code indentation at the document root remains literal, while an active list container contributes a
block indent that must be removed before applying the four-space code/table distinction. Four forms ×
ten owners × loose bullet, loose ordered, quoted-bullet, and nested-bullet header/body contexts add 160
container-relative table rejections. Table-looking source after an explicit root paragraph boundary and
four-space code indentation, plus a complete title in an inherited-list table cell, add two controls.
CommonMark tabs advance to four-column stops. One bounded indentation view records visual columns and
exact raw-source offsets, recognizes tabs as valid list-marker padding and continuation indentation,
and removes only a proven active list content indent before the code/table decision. Four forms × ten
owners × four tab-padded-marker, four tab-indented-continuation, four nested partial-dedent, one quoted
inherited-body-row extent, plus one lazy body-row context add 560 rejections. A tab-indented table-looking block at the
document root remains literal code, while complete titles inside one tab-padded-marker cell and one
tab-indented-continuation cell remain non-rendered; all three add controls. The view never globally
rewrites source bytes or loses raw error/boundary locations.
A locally balanced second reference label receives no non-rendered provenance without a matching
definition: unresolved full link/image source renders literally under GFM. The alpha checker therefore
retains second-label bytes in the raw-HTML provenance channel instead of implementing a partial
reference resolver. The separate visible-label normalizer may elide the suffix to isolate a rendered
primary label, but cannot hide HTML from provenance analysis. Four link/image/nested forms × ten owners
× paragraph, bullet, table-header, and table-body contexts add 160 rejections; ordinary unresolved link
and image labels add two controls.
Sixteen matched, escaped, closer-only, asymmetric-tilde, and code forms over five owners
provide 80 accepted controls proving that an ordinary period reference outside an unrelated delimiter
span remains valid. Two noncrossing/foreign-width code compositions plus six visible unmatched
emphasis/tilde prefixes inside an HTML run over five owners add 40 accepted matched-syntax controls;
those 120 delimiter controls plus the three general label-ownership controls and five table-ownership
controls remain outside rejected arithmetic. Only complete canonical raw definition
syntax including the closing bold delimiter is accepted as a definition. The aggregate harness
exercises duplicate and unknown IDs from all four families across 24 wrappers and eleven contexts: bare
paragraph, bullet, numbered, five GFM table encodings, blockquote, heading, and task list. A separate five
table encodings × five blockquote/bullet/numbered/heading/mixed-prefix families × eight IDs matrix closes their composition; another
five encodings × task/exact-64/exact-65 prefixes × eight IDs matrix closes the boundary composition. The
remaining unordered/ordered empty/lower/upper task-marker forms add 40 direct cases. Later-table
metadata strips the same bounded structural and list-task prefixes before table splitting. Its first cells are
compared by their rendering-normalized NFKC/case-folded label. For the three version/product-contract
linkage labels, a conservative ordered-source check also rejects non-visible or reference markup
inserted between their characters; escaped table pipes are parsed as cell content rather than
delimiters, and any bidi control fails before either comparison. Valid fenced rows are excluded through
the shared provenance rather than mistaken for later tables. It exercises all 12 bidi controls in
literal, decimal, and hexadecimal form for each linkage field plus named LRM/RLM entities. Its 385-case
document/version partition is explicit: 13 direct initial/linkage + 18 duplicate-row + 54 disguise +
180 three-field/five-encoding/twelve-prefix-or-task structural tables + 6 single-line declaration/PI +
114 complete-property bidi. Trailing Markdown-wrapper/outer-HTML provenance accepts at most 256 combined
candidates per line before suffix interpretation; the exact boundary is positive and the next candidate
fails closed. An explicit KMP membership scan relates each fragment to the complete rendered suffix, so
repeated bounded fragment rendering remains a constant-factor linear pass. The
independent harness rejects all 8,302 named mutations through exactly one runtime `check_all` entry per
callback; all 78 static rejection sites supply a narrow expected reason.
It asserts each category, definition family, and executed total. Definition arithmetic is
`35+20+160+140+20+560+320+240+160+560+160+30+1+2112+40+144+352+16+16+200+34+32+264+32+8+60+20+20+8+16+80+80+180+120+1+1+1 = 6,243`:
direct, legacy trailing, rendered-suffix trailing, visible-HTML period trailing, Markdown/HTML context,
block-crossing link context, block-crossing visible-label context, GFM-table label ownership,
container-relative inherited-list table ownership, tab-stop-aware list table ownership, visible
unresolved-reference labels, single-cell pipe, ordered start-one paragraph interruption,
wrappers, task
markers, format characters, bidi, Setext, nested prefixes, structural-prefix tables, colon, structural
HTML, visibility, multiline HTML, escaped code, HTML boundaries, invalid fences, terminated-container
fences, malformed/depth HTML, inline-code structural cells, inline/block boundaries, tab-padded
inline/block boundaries, short-Setext/over-padded-list inline boundaries, task/depth tables,
document bound, normalized bound, and trailing-provenance candidate bound respectively. The total is
1,476 operation + 30 catalog + 385 document/version + 6,243 definition + 7 maintenance + 7 lifecycle +
7 addressed-state + 7 generation-guarded + 23 complete-revision + 66 incarnation-allocator + 27
upgrade-exit-capacity + 12 release-integrity + 12 evidence-parity = 8,302.
An unrelated checker exception/
error class, dead aggregate branch,
family drift, or total drift fails the harness. Ordinary references, exact accepted boundaries, valid
owned-blank container fences, fenced metadata, linear-work checks, and genuinely visible HTML/code/
autolinks are positive assertions outside the rejected total.

### A-17.2. Hermetic and fault boundaries

Standard tests run with public egress denied. Production connector construction in test profiles
accepts only loopback fixtures; a second listener detects redirect or proxy disclosure. Injected
clocks, IDs, MACs, random sources, disk probes, store commit/barrier failures, worker stalls, and
process kill points make edge cases deterministic. Crash suites run the real binary and inspect only
committed state after restart rather than mocking the property under test.

Startup-version evidence injects runtime SQLite numbers immediately below, exactly at, and above
3.51.3. The below-floor case fails before readiness; exact and above cases expose the measured version
and continue into the complete profile verification.

Authentication scheduling evidence fills all 16 header/preclassification slots with partial headers,
crosses the five-second and 16-KiB/64-header boundaries, and proves bounded uniform release without
claiming a valid-request deadline. It then starts the measured clock only after complete-header/index
classification, saturates unknown-ID dummy shards plus one known public ID from many sources, and
proves a valid different ID completes verifier plus durable-row/epoch recheck within 250 ms. The
attacked ID leases one permit globally; distinct-ID and per-ID queue 64/65 and 8/9 boundaries reject
excess safely. A valid different ID is injected specifically as the 65th distinct ID and as the ninth
request behind one ID during the one-known-ID flood; each receives only the uniform retryable
saturation result, never leases a known-ID permit, and leaves a separately admitted different-ID
250-ms path unchanged. A separate explicitly out-of-SLA many-enabled-ID flood remains bounded. Loom plus
process tests race principal enable/disable and API-key issue/rotate/revoke commit, immutable-index
publication, response wake, and verification recheck: no response precedes its epoch, publication is
monotonic, and a stale snapshot never grants authority. The generation-guarded principal/grant matrix
drops both effect and no-op responses at transaction commit, index publication, response wake, and
disconnect, then retries before and after restart. Exact complete-address current-receipt recovery returns once; an
opposite transition by the same/different actor, same-value ABA, unrelated principal/grant-collection
advance, stale/future generation, old incarnation, and changed semantic body all return
`state_generation_conflict` without a second audit row, credential/grant revival, or epoch regression.
Disabling or descoping the original actor denies receipt disclosure; a distinct authorized actor
conflicts. A lost same-value no-op followed by a different desired request at the still-current complete
address commits that deliberate fresh change once, while the old no-op remains effect-free. For all five
operations, a pre-request backup plus lost response is followed by restore or rollback, same-stable-
actor reauthorization, resume, restart, and retry; the numeric generation may collide, but the old
incarnation always conflicts. Repeat every non-key generated ID/random value and construct a blank-host
restore from an artifact that predates an abandoned descendant; with independently injected fixed-root
keys, the old request still conflicts after actor reauthorization even when serial and generation
numbers collide.

Allocator fault evidence covers the exact bootstrap/restore/rollback registry and every continuation.
It injects OS-entropy error, short fill, all-zero sample, and equal journal/portable samples before root
initialization; no usable key, journal, intent, generation, or pointer may result. It repeats every
non-key random/ID output and proves each fresh allocating intent burns exactly one serial while every
continuation burns none. Crash before and after each key, header, intent, staging, finalization,
certificate, pointer-rename, and parent-fsync barrier; same-intent recovery must reuse one exact target,
and aborted or terminally failed work never reclaims it. Force collision with active, retained-parent,
retained-sibling, nonterminal-intent, and identifiable staged targets plus source/parent and target/
serial mismatch; each returns `state_incarnation_unavailable` in bounded work before selection or
pointer mutation and never rerolls. Exercise serial one, both 32-bit carry seams, `u64::MAX - 1`, and
`u64::MAX` without wrap. At maximum, exact same-command recovery remains available; a forbidden
restore/upgrade hold wins without allocator disclosure, while a transition permitted through its own
hold returns allocator unavailability before `clock_hold` and preserves that hold. Reject every wire,
artifact, configuration, environment, and CLI attempt to choose namespace, serial, target, or high-
water. Clone/import of one fixed root into concurrently live hosts is an explicit unsupported-deployment
test, not a claimed deterministic cross-host uniqueness proof.

Upgrade-headroom evidence invokes `upgrade.prepare` at branch serial MAX and MAX−1. MAX refuses before
coordinator, hold, admission, journal, or allocator mutation; MAX−1 prepares, rollback burns MAX exactly
once, and same-command rollback recovery remains available at MAX. With usable serial headroom, a
nonterminal drain, and pure clock hold, fresh prepare returns `clock_hold` before drain/capacity
disclosure in both actor orders and leaves allocator, binding, coordinator, and drain state unchanged.

Recovery-composition evidence substitutes a complete older authenticated journal with lower high-water
than retained local witnesses and requires corruption hold before selection, then substitutes an equal-
high-water image missing only reconstructable terminal suffix truth and requires convergence without
authority loss, safe-time regression, or duplicate burn. It also performs blank restore A→B, backup on
B, and blank restore B→C across startup, fold, and anchor compaction; every artifact-internal boundary
remains verified foreign ancestry. With one guarded generation and the branch serial both at MAX, API,
CLI, and metrics retain both closed reasons while CLI recovery guidance names only the independently
keyed new-root path.

Storage tests cross both two-limb carry seams and inject `u64::MAX - 1`/`u64::MAX` into admission,
principal, and grant resources. Every applicable guarded operation plus `principal.update` and fresh
`drain.start` reaches MAX once from MAX-1. At MAX, fresh writers fail before resource, receipt, epoch,
audit, command, or coordinator state, while exact receipt/no-op/command recovery remains available.
Schema tests reject negative/oversized limbs, zero, invalid carry, partial receipts, receipt/resource-
incarnation mismatch, and any live resource incarnation unequal to the selected authenticated history
epoch.

JSON ingress evidence constructs otherwise-valid requests at exactly 64 and 65 simultaneously open
arrays/objects. Depth 64 reaches typed validation; depth 65 returns the stable malformed-JSON `400`
before any store command. The over-depth request is repeated on a reduced-stack debug thread and must
not panic or overflow. Cargo feature inspection fails if serde_json `unbounded_depth` appears anywhere
in the resolved production feature graph.

AC-028 has two layers. The default hermetic gate injects commit/barrier failures and structurally checks
production pragmas plus file/directory fsync calls. The Linux release gate additionally uses an
ephemeral loopback/ext4 device-mapper `dm-log-writes`/`dm-flakey` harness to replay prefixes of the real
binary's writes at enqueue, DB/WAL/key creation, backup publication, generation finalization, pointer
rename, and directory-fsync boundaries. The privileged harness is release-only, never production code,
uses a validated temporary device target, and destroys no host volume. A returned acceptance must exist
in every stable prefix after its barrier; generation recovery must select one whole committed state.
For backup, the oracle enumerates temp fsync/parent fsync, `artifact_staged` FULL commit, no-replace
rename, publication parent fsync, completion/provenance FULL commit, cancellation unlink/fsync, and
retention unlink/fsync. After each replayed prefix, startup reconciliation must yield either one
digest-matching `complete` final artifact plus provenance, or one explicit non-complete job with no
owned file and correctly retained/released pin; no other filesystem/SQLite pairing is accepted.
Before fault injection, a schema/creation test requires non-null validated-safe-UTC execution-deadline,
component-maximum/margin, and same-boot monotonic-mirror carriers in every nonterminal `backup_jobs` row
and proves retention/support fields cannot substitute for them. Repeated restart at each copy/
verification/publication prefix reconstructs a conservative remainder from those exact durable bytes
without extension. At every prefix, cancellation intent committed before a later clock hold may finish
only unlink/fsync/terminal/pin-release work, while a newly submitted `backup.cancel` under the hold
returns exact `503 clock_hold`, null hint, and byte-for-byte unchanged job/filesystem state.

For rollback-eligible upgrades, the oracle holds smoke beyond a checkpoint interval and crashes every
`clock.checkpoint`, `clock.acknowledge`, and `system.shutdown` fixed-journal publication/file barrier and
selected-SQLite mirror boundary. It accepts only a gapless authenticated checkpoint/tail transcript and deterministic projection, an idempotent mirror,
and either a still-held `deadline_derivation_pending` marker with unchanged message/circuit deadlines or
one selected hold-clear transaction that derives all pending deadlines before effects resume. Prepare
faults include a worker crash through the longest persisted lease expiry/fence recovery and every
in-flight backup publication/reconciliation phase before the stable watermark proof. They also cover
drain/prepare actor order, terminal failed-prepare commit/restart, an admitted-backup maximum deadline,
automatic settlement and its event-triggered checkpoint, and SQLite/fixed-root caller-key expiry across
the rollback window through pruning on every selected hold-clear path. They first prove idempotency,
generic command, foreign-namespace, and local/portable fixed-root expiry, then enter a later anomaly and
crash every high-water checkpoint/mirror prefix; proven authority remains absent while unresolved
comparisons and every fresh effect stay held. Replay races admission close, drain's zero-remainder
terminal transaction, and prepare's first quiescing transaction in both actor orders.

Normal-mode clock-settlement evidence reads the exact hold-generation/observation address, rejects
stale/future/different addresses, and independently crashes both explicit acknowledgement and automatic
checkpoint publication after unique-temporary write, file fsync, atomic replacement rename, and parent-directory
fsync, then before/during/after the selected FULL mirror. Every prefix is either still held with no
scheduler-visible deadline or one atomically projected hold clear; exact newest-current/completed retry
before a newer hold converges without a command key or projection growth. A combined cross-actor matrix
crosses both addressed-state operations with changed grace/observation value, current/last/completed/
stale/future address, newer hold/process generation, and a second actor while losing the response at
unique-temp write, file fsync, replacement rename, parent fsync, and SQLite mirror prefixes. Every
prefix has one total current result, no repeated effect, and exactly four projection cells.

Prepare evidence reads admission address `(I, G)`, drops an `admission.set closed` response after its
durable `(I, G+1)` admission-row/incarnation-bound-receipt commit, and restarts on both sides of the first
quiescing transaction. `admission.show` and exact same-actor/closed-semantics/complete-address receipt recovery
return the current committed tuple. A later opposite transition supersedes the receipt, and retrying
the old request returns `state_generation_conflict` without reopening. A lost phase conflict has no
receipt and is re-evaluated only while its complete expected address remains current. Under a pure clock
hold, exact current-receipt recovery or a complete-expected-current same-value no-op returns the tuple
before hold checks; a complete-expected-current different value enters no coordinator and returns exact `clock_hold`.
During a nonterminal prepare plus clock hold, those effect-free paths still return the tuple, an older
complete address returns `state_generation_conflict`, and a complete-expected-current different value returns
`upgrade_prepare_in_progress` before clock evaluation.

Drain evidence loses a same-value no-op response, accepts a fresh drain while admission is open and
while already closed, and crashes after generation advance/receipt clear/command commit through both
terminal outcomes. Same-key drain recovery never advances again; every old no-op retry conflicts and
cannot reopen admission. At admission MAX, fresh drain creates no command or coordinator and emits the
exact exhaustion/readiness result.
Prepare evidence also persists the immutable safe-UTC deadline/component proof, crashes repeatedly
across restart, and proves its reconstructed monotonic remainder never extends. It commits every
provider outcome under the total accepted/cancel/expiry/exhaustion order; only remaining nonterminal
truth enters `upgrade_quiescing`. Later cancel/deadline guards cannot escape through generic
maintenance. Matching late provider acceptance promotes each of `failed`, `cancelled`, and `expired`
exactly once before/after restart and through upgrade-held projection; unmatched, unverifiable,
ambiguous, and non-acceptance callbacks remain terminal no-ops. The suite crashes release after prepare failure, activation, rollback clone, and forward
repair, both with safe time and with conversion to a stricter clock anomaly. The oracle accepts exactly
one retained-outcome projection, one shared auth/config circuit probe, and never a null-deadline eligible row.

Upgrade-exit-capacity evidence derives the complete binding independently from the closed plan and
codec maxima, then crosses the ordinary entry and byte boundaries by one. Rejection proves byte-identical
fixed-root, selected-state, coordinator, hold, admission, and allocator state. Exact fit publishes one
authenticated binding before the selected coordinator. Unrelated ordinary admission sees unconsumed
reserved capacity as occupied. Separate migrate-activate, migrate-rollback, and divergence-forward-
repair executions consume only their named roles without another ordinary-capacity decision and retain
the dedicated rollback role until phase exit. A composed migrate → rollback serial burn → authenticated
mismatch → durable divergence → forward-repair execution proves the conservative sum retains the
consumed rollback projection, repair role, and maximum shared projection at once. Every incompatible
fixed-root journal format, framing, MAC-key format, or per-role codec version fails before role
consumption while compatible continuation or rollback authority remains. Crashes surround the prepare intent, coordinator, every
role conversion, fold, selected terminal, fixed-root mirror, and release; restart never observes an open
phase without the complete binding or a closed phase with stale reservation. Pre-burn rollback
validation failures consume neither serial nor role. Post-burn I/O prefixes remain same-command
recoverable, and an authenticated mismatch retains bound divergence plus forward repair rather than a
terminal rollback with no exit.

Fixed-root capacity evidence injects smaller test constants while preserving all production ratios.
One case holds rollback eligibility through many multiples of the 128-record tail cap; another holds the
sole `pending_escrow` successor for the same duration. Each periodic publication repeatedly folds the
tail while the image stays within exact byte/entry caps and the authenticated command, reservation,
ring, safe-time, and upgrade transcript/mirror projections remain identical to a reference reducer.
Crash the unique-temp write, file fsync, replacement rename, parent fsync, restart validation, and final
activation/rollback/retirement barriers on both sides of every fold. Fill the
`4 MiB - 16 KiB`/4,032-entry ordinary checkpoint budget exactly, prove the next resource-growing operation returns `control_capacity` with no intent
or side effect, and then prove the admitted 64-record worst-case coordinator, one lifecycle publication,
key-independent terminalization, and capacity-reducing retirement remain possible from the reserved
2-MiB/64-entry checkpoint reserve plus the independent 2-MiB tail. The non-addressed reconciliation projection is capped at 60 entries; two current/two
last addressed-state cells make the exact remaining four. With ordinary capacity full, run more than
64 alternating clock-hold/process-instance cycles through response loss, fold, and restart and prove
those four cells replace in place while the next settlement and pending-escrow retirement still publish.
In the same exact-full case, keep an open upgrade transcript and quiescent `pending_escrow` successor
simultaneously live, then publish the 64-record coordinator terminalization, one lifecycle record, one
key-independent retirement, and one resolved-provenance fold solely through the 60-entry/2-MiB
reconciliation region plus 2-MiB tail. Crash every fold/replacement barrier on both sides and exceed no
byte or entry cap.
Separately repeat divergence/repair/dependency-checked generation deletion, advance durable safe time
across the frozen audit deadline, and crash each fold barrier: only resolved/expired/dependency-free
pairs disappear, and enough cycles to overflow without omission retain a bounded live projection. At production constants, property tests independently recompute every encoded-length
sum and prove complete parse/validation work is linear in at most 8 MiB.

Backup fault evidence schedules prefix compaction after job creation and at every copy/verification/
publication boundary. The conservative running pin must prevent the anchor crossing before step 4;
completion converts it to exact provenance, while failure/cancellation releases it only after durable
artifact removal. At every same-boot/restart prefix, inject a later clock hold: no new copy, verification,
rename, or completion occurs; crash-safe reconciliation cannot claim success; settlement either resumes
the same prefix within the original immutable deadline or, after proven expiry and owned-artifact
removal, commits one loud terminal failure and releases the pin. Compose each prefix with prepare so an
unprovable held backup blocks the watermark rather than extending time or freezing a half-publication.

Backup/store compile evidence pins `Transaction::new_unchecked(&Connection,
TransactionBehavior::Immediate)` while a retained backup handle exists, rejects every `&mut self`
transaction/savepoint helper and raw transaction-control statement on that path, and proves every normal
transaction consumes an explicit result-bearing commit/rollback/finish. Faults after partial statements
exercise successful explicit rollback and rollback failure separately. The latter must poison the actor,
stop commands and backup steps, degrade readiness, drop the handle/connection, reopen under the full
startup gate, and reconcile one durable prefix before monotonic backup progress resumes within the
unchanged deadline; RAII remains only the unwind backstop.

Capacity evidence uses the documented Sol hardware/filesystem/SQLite profile, command size mix,
concurrency, warmup, duration, percentiles, fairness workload, backup concurrency, and resource usage.
The requirement is a regression floor, not permission to change durability or skip fsync.

### A-17.3. Required clean-checkout gate

The gate runs formatting check, all-target/all-feature Clippy with warnings denied, workspace tests,
documentation tests, release build, MSRV check, `cargo deny` advisories/licenses/bans/sources, source
static analysis, secret scan, filesystem/container/artifact vulnerability scan, SBOM/provenance and
API dynamic security tests against loopback. Production code forbids unsafe, `unwrap`, `expect`, panic,
`todo`, `unimplemented`, `dbg`, ignored results, and unchecked numeric casts through lint plus source
tripwires. Store-specific source/compile gates reject raw transaction control and implicit normal-path
Drop completion in the shared-borrow backup transaction wrapper, while permitting the pinned safe
`new_unchecked` call. The complete gate passes twice from clean checkouts before tagging.

Release assembly verifies every publishable crate reports exactly `0.1.0-alpha`, builds with the
committed lockfile, produces binary/source checksums, SBOM and provenance, links the two clean-gate runs
plus live ntfy evidence, then creates the annotated tag. No moving/recreated lightweight tag or
dirty-worktree artifact is a release candidate.

Agentic exploratory QA runs after deterministic gates with read-only evidence access and isolated
fixtures. It attacks operation parity, auth confused-deputy paths, provider schema leakage, queue
starvation, ambiguous effects, backup/restore, CLI disclosure, generic-driver future seams, and
operator recovery. Exploratory discoveries become reproducible RED regression tests before fixes.

## A-18. Traceability, support claims, and evolution

### A-18.1. Generated evidence ledger

`specs/traceability.md` maps every first-slice `PR-*`, `INV-*`, `A-*`, and `AC-*` to contract tests,
implementation symbols, gate artifacts, and—where required—live evidence. CI fails on an unclassified
normative product requirement, missing operation descriptor, unknown test ID, or support claim without
the required evidence. It refuses to generate or accept the ledger until every definition key is
globally unique, so one row can never satisfy two normative definitions accidentally. Generated
portions are mechanically checked; rationale and waivers remain reviewed text.

Provider support is reported independently as Contracted, Implemented, Proven, or Planned. The binary
catalog can never advertise a driver compiled out or a support level above its release manifest.
Version `0.1.0-alpha` proves native ntfy on Linux/Sol only; fake drivers are test evidence, and planned
generic HTTP, email, SMS, WhatsApp, Teams, Slack, or ntfy features are not implied.

The traceability universe is generated, not authored. A read-only extractor derives an immutable
candidate universe from exactly three root inputs: the release-canonicalized bytes (`utf8-newlines-v1`:
strict UTF-8 decode, CRLF and lone CR mapped to LF, exactly one terminal LF, every other byte preserved)
of `specs/product.md` and `specs/architecture.md`, plus the exact bytes of `specs/release-identity.toml`
that pin their digests. It consults no case, observable, ownership, or coverage artifact. Manifest path,
declared format/version, and digest equality are checked before document parsing; a mismatch emits no
candidate universe. `scripts/spec_structure.py` owns the shared bounded API
`parse_spec_structure_v1(canonical_document, canonical_path)`, which both `scripts/check_specs.py` and
`scripts/extract_spec_universe.py` import; there is one shared parser and no second Markdown channel. The
API returns source-provenance spans for ATX headings, complete list items, non-overlapping leaf blocks,
fences, tables, table header/separator/body rows and cells, plus offset-aware visible, code-span, and
autolink channels. Its frozen order is fence tokenizer → HTML visibility → offset-preserving Markdown
pass → NFKC, and unsupported or structurally ambiguous Markdown fails closed. Neither caller may
reconstruct a span, infer a table independently, or apply a second definition regex;
`scripts/check_spec_universe.py` owns artifact validation and invokes the extractor in memory, so no
checker parses Markdown independently.

The frozen ownership tree gives every emitted source region exactly one structural owner: the innermost
definition list item, otherwise the innermost section, otherwise the document. Exactly one structural H1
returned by the shared parser begins at byte zero, is the document title, and emits no section; any later
structural H1 fails. Every later structural heading is an unindented ATX heading of depth 2–6 whose source
begins `#{depth} SP`, followed by the document's own `P-\d{2}(?:\.\d+)?` or `A-\d{2}(?:\.\d+)?` identifier
and its terminating period; closing ATX hashes, a skipped parent depth (with H1 as depth 1), a foreign
prefix, a duplicate section ID, and any other structural depth-2–6 heading all fail closed, and
heading-looking bytes inside fences, code spans, tables, or modeled raw HTML are not structural headings.
On a valid heading the section stack pops every heading of equal or greater depth and then appends the new
heading; its complete identifier chain is the section owner until the next pop. A `definition` is a
container-depth-zero unordered list item returned by the shared parser whose first inline run begins with a
closed ID (`PR-\d{3}`, `AC-\d{3}`, `NG-\d{3}` in product; `INV-\d{3}` in architecture) in either frozen
bold form, with its closing `**` in that run; it owns its complete parsed list item, so lazy and indented
continuations, later paragraphs, and nested child blocks end only where the shared list-item span ends, and
a lookalike in a nested list, blockquote, table, fence, raw-HTML structural container, or a later run is
never a definition. Each document, section, and definition owner has one 1-based direct-child source
sequence: a child section, definition, non-overlapping textual leaf block, fenced-code block, or table each
consumes exactly one position while its descendants do not. A section records its position as
`section_ordinal`; a definition records `definition_ordinal`; a direct block or table records
`block_ordinal`; each definition owner has its own 1-based direct-child sequence for textual blocks,
fences, and tables, also recorded as `block_ordinal`. Thus moving content across a definition or subsection
changes a path even when the moved unit's same-kind ordinal would not.

The structural units are the closed set `{document, section, definition, block, table, table_row, clause}`,
each with a frozen coverage role:

| Kind | Derivation | Coverage role |
|---|---|---|
| `document` | one per canonical path | container |
| `section` | heading with exact identifier and depth (`P-*`, `A-*`) | composite, earns zero atomic coverage |
| `definition` | canonical named definition in either bold-bullet form (`- **PR-061.** …`, `- **PR-001 — title.** …`) and the AC/INV/NG variants, requiring the closing bold delimiter | composite, earns zero atomic coverage |
| `block` | one non-overlapping `paragraph`, `list_item`, `blockquote`, or `fenced_code` leaf block in the owner's shared ordinal sequence | container |
| `table` | a contiguous Markdown table recognized by the shared parser | container, earns zero atomic coverage |
| `table_row` | each nonseparator body row after the single header separator, in source order; the rendered visible content is the ordered cell sequence joined by U+001F | leaf; cells and header are never separate units |
| `clause` | sentence-level leaf inside a non-table, non-fenced block, produced by the frozen splitter below | leaf |

A textual leaf is the parser's maximal inline-bearing paragraph; its public block kind is `list_item` when
its nearest textual container is a list item, `blockquote` when it is inside a blockquote, and `paragraph`
otherwise, and list-item and blockquote containers do not emit overlapping blocks. A fence emits one
`fenced_code` block and no clause; a table emits one `table` at its position in the same direct-child
sequence and no overlapping block; empty visible blocks still emit their container but no leaf; and H1 and
blank lines consume no position. Because a section, definition, table, or document span is composite and
earns zero atomic coverage, citing `PR-085` or `A-11.3` as a whole earns exactly zero atomic credit.

The shared parser supplies every structural unit's visible text and exact source provenance through
`render_visible_v1`, which is part of that parser. `render_visible_v1` removes proven structural and
matched inline markup, preserves visible link/image labels and code-span/autolink payloads, decodes modeled
HTML entities and visible text, rejects unsupported visibility, and applies the existing bounded NFKC and
default-ignorable policy, returning both the rendered text and provenance tags for inline-code and autolink
output. Its `semantic_text` replaces every nonempty run of rendered whitespace, including a soft line break,
with one ASCII space and trims the two ends, so semantic whitespace folding never hides a source edit from a
content digest. For each unit the parser supplies its exact half-open slice of the already
release-canonicalized source: a non-document structural span begins at its first structural or source token
and ends immediately after its last token, excluding the following LF and blank-line separators while keeping
internal soft-break LFs and horizontal whitespace; the document unit alone is the complete canonical document
including its one terminal LF; a clause slice is the smallest contiguous source slice from its first
contributing visible token through its final contributing token or terminator, including intervening markup
but excluding structural prefixes and separator whitespace after a boundary; and a table-row slice excludes
its terminating LF but includes its raw delimiters and cell whitespace. `visible_bytes` is the unit's UTF-8
`semantic_text`; for a table row it is instead each cell's `semantic_text`, including empty cells, joined in
order by UTF-8 U+001F, and no per-unit newline is added. With `LP(x) = U64BE(length(x)) || x`, the content
digest is therefore:

```text
content_sha256 = SHA-256("msgriver/spec-content/v1\0" ||
                        LP(exact_source_slice) || LP(visible_bytes))
```

Markup and trailing horizontal whitespace remain identity-relevant even when they render to the same
semantic text; offsets and line numbers select the slice but are not themselves hashed.

The frozen sentence splitter produces `clause` leaves. A clause boundary is `.`, `;`, or `:` followed by one
ASCII space or end-of-block in `semantic_text`, where the terminator is not (a) provenance-tagged as inside
inline code or an autolink, (b) the trailing period of a canonical ID token (`PR-001.`, `AC-031.`), (c)
inside a decimal number, or (d) the internal or trailing period of a section reference (`P-07.1`, `A-11.5`,
`P-07.1.`). The terminator belongs to the preceding clause; separator whitespace belongs to neither clause.
Fenced code, tables, headings, and an empty visible block contribute zero clauses, and the splitter is
deterministic, bounded, and independently mutation-tested.

The shared table rule is frozen. The shared Markdown parser supplies table, header, separator, body-row, and
cell boundaries; the extractor never infers them independently. A table has exactly one structural header
and separator; every subsequent nonseparator body row emits exactly one `table_row`, while the header,
separator, and cells emit no units and the row emits no child clauses. Table rows use the same total leaf-
classification rule as clauses and never inherit an undefined "normative section" property.

For every `clause` and `table_row`, the parser MUST set `normative = true` exactly when the leaf's own
non-code, non-autolink `semantic_text` contains an uppercase keyword from the closed MsgRiver normative
set defined by P-00, `{MUST NOT, SHOULD NOT, MUST, SHOULD, MAY}`, regardless of whether the leaf sits
inside a numbered definition. A keyword is case-sensitive and bounded on both sides by start or end of
text or a byte outside ASCII `[A-Za-z0-9_]`, so `MUSTARD`, `MUSTard`, inline-code text, and autolink
payloads do not match.

When that normative keyword is absent, the parser MUST set `normative = false` and `ambiguous = true` for
the leaf. The `ambiguous` field means review-required non-normative evidence; it does not assert that the
prose is linguistically ambiguous. Every leaf MUST carry exactly one of the two flags, while every
container MUST carry neither. A phrase or heuristic screen MAY prioritize review order, but it MUST NOT
change a flag, exclude a leaf from ownership, or contribute to a completeness claim. Consequently every
leaf is flagged and enters explicit ownership review.

Coverage of named definitions follows directly. A testable leaf is every normative leaf plus every
ambiguous leaf whose reviewed classification is not `context`; a `definition` is satisfied iff it has at
least one testable child and every one of its testable child leaves (`clause` or `table_row`) is satisfied,
and a definition with no testable child carries no satisfaction claim. The definition's own span earns no
coverage, so citing a definition as a whole earns exactly zero atomic credit.

Unit identity is a pure function of immutable canonical bytes. Reusing `LP`, the path and unit identifier
are:

```text
PATH_V1 = "msgriver/spec-path/v1\0" ||
          LP(UTF8(unit_kind)) || LP(UTF8(document_path)) ||
          U16BE(section_count) || for each section:
            U8(section_depth) || U64BE(section_ordinal) || LP(UTF8(section_id)) ||
          LP(UTF8(definition_id_or_empty)) || U64BE(definition_ordinal_or_zero) ||
          U64BE(block_ordinal_or_zero) ||
          LP(UTF8(block_kind_or_empty)) ||
          LP(UTF8(leaf_kind_or_empty)) || U64BE(leaf_ordinal_or_zero)
unit_id = lowercase hex of first 16 bytes of
          SHA-256("msgriver/spec-universe/v1\0" || LP(PATH_V1) || content_sha256_raw_32_bytes)
```

`unit_kind` is the closed set `{document, section, definition, block, table, clause, table_row}`;
`block_kind` is the closed set `{paragraph, list_item, blockquote, fenced_code}` for a block and its clause
children, empty otherwise; and `leaf_kind` is `clause` or `table_row` only for leaves. Ordinals are 1-based
where applicable and the binary zero sentinel otherwise; a section's chain includes itself and each
element's exact depth and direct-child ordinal, and all lengths, depths, counts, and ordinals are
bounds-checked before encoding. No human names a unit; no line number or byte offset participates.
Relocating unchanged text changes the owner or ordinal path and therefore `unit_id`; editing source or
visible text changes `content_sha256` and therefore `unit_id`. The extractor rejects duplicate `PATH_V1`
before hashing, then rejects duplicate full SHA-256 and duplicate truncated `unit_id` separately, so codec
aliasing can never be reported as a probabilistic collision; there is no locator syntax to alias, because
cases name a `unit_id` and nothing else.

The four E5 codec known answers are frozen before the extractor code or tests. All four synthetic units use
`document = "specs/product.md"` and one section-chain element `(depth=2, section_ordinal=1, id="P-00")`;
source and visible strings below have no terminal LF and `\x1f` is one U+001F byte:

```text
E5_KAT_01_SOURCE_HEX  = 4d55535420706572736973742e
E5_KAT_01_VISIBLE_HEX = 4d55535420706572736973742e
E5_KAT_02_SOURCE_HEX  = 4d55535420706572736973742e
E5_KAT_02_VISIBLE_HEX = 4d55535420706572736973742e
E5_KAT_03_SOURCE_HEX  = 7c204d555354207c2070657273697374207c
E5_KAT_03_VISIBLE_HEX = 4d5553541f70657273697374
E5_KAT_04_SOURCE_HEX  = 4d55535420706572736973742e2020
E5_KAT_04_VISIBLE_HEX = 4d55535420706572736973742e
```

| KAT | Remaining `PATH_V1` fields | Exact source / visible bytes | `content_sha256` | full unit SHA-256 / `unit_id` |
|---|---|---|---|---|
| `E5-KAT-01` plain clause | `kind=clause`, no definition, `block=1`, `block_kind=paragraph`, `leaf_kind=clause`, `leaf=1` | `MUST persist.` / `MUST persist.` | `86f61e6affd7169dc34403694ae7fc49e13ea3cc12dd60904c6213d4add24db5` | `013fb55b9c39c8180ed9c1fbc5ceea778e7c7422c80a143d5477d57d810e9d9e` / `013fb55b9c39c8180ed9c1fbc5ceea77` |
| `E5-KAT-02` definition clause | `kind=clause`, `definition=PR-001`, `definition_ordinal=1`, `block=1`, `block_kind=list_item`, `leaf_kind=clause`, `leaf=2` | `MUST persist.` / `MUST persist.` | `86f61e6affd7169dc34403694ae7fc49e13ea3cc12dd60904c6213d4add24db5` | `ca6495b2ba834ea14149f0fac3f8ecb6fa2b519a7c92382bb51750baa21bda08` / `ca6495b2ba834ea14149f0fac3f8ecb6` |
| `E5-KAT-03` table row | `kind=table_row`, no definition, `block=1`, empty `block_kind`, `leaf_kind=table_row`, `leaf=1` | `\| MUST \| persist \|` / `MUST\x1fpersist` | `84113b8f39d5477b633e4332c0e599a99388e6d4c61a59a57331c7b1b61059aa` | `132da2389c919853a2a46e0c7fd55531a79eeb70b893e8fc9c06c38847b1aa15` / `132da2389c919853a2a46e0c7fd55531` |
| `E5-KAT-04` trailing-space block | `kind=block`, no definition, `block=1`, `block_kind=paragraph`, no leaf | `MUST persist.␠␠` / `MUST persist.` | `f16011e2c229648240806d3ef99ac16dd05e5513894b7208454dc15946d98945` | `eb99f653b4ea2a26156a16637152585285ad9939819807b05122e88933ec758c` / `eb99f653b4ea2a26156a166371525852` |

The recomputation is mechanical: `LP(x) = pack("Q>", bytesize(x)) || x`; construct `content_sha256` and
`PATH_V1` exactly as above; compute the full unit digest over the domain plus `LP(PATH_V1)` plus the raw
32-byte content digest; truncate only after the full-digest collision checks. Any E5 implementation that
derives its expected known answer from its own output is invalid evidence.

The generated traceability chain is a fixed six-artifact order: (1) the canonical documents, (2)
`specs/release-identity.toml` which pins the exact bytes of (1), (3) `specs/spec-universe.toml` generated
by the extractor from (1) and (2) and never hand-edited, (4) `specs/core-ownership.toml`, (5)
`specs/atomic-observables.toml`, and (6) `specs/contract-cases.toml`. Within that order the four-artifact
ownership chain (3)→(4)→(5)→(6) is enforced: artifact (3) is regenerated in memory from (1) and (2)
before any ownership, observable, or case artifact is read, so an authored artifact can never bless
itself; an observable requires ownership (`observable_requires_ownership`) and a case requires an
observable (`case_requires_observables`), each naming exactly one scalar testable leaf `unit_id`. A
composite, list/set, duplicate-aliased, unknown, container, or context `unit_id` is rejected
`observable_not_atomic`. At the final full-observable gate there is exact one-to-one equality between
testable `unit_id`s and observable `unit_id`s.

Each generated artifact has an exact schema. `specs/spec-universe.toml` is canonical UTF-8/LF with one
terminal LF, no timestamp, and no implementation-dependent map iteration; its top-level scalars are
`format = "msgriver/spec-universe/v1"`, `product_sha256`, `architecture_sha256`,
`release_identity_sha256` (the exact manifest bytes validated), `parser = "parse_spec_structure_v1"`,
`renderer = "render_visible_v1"`, `path_codec = "msgriver/spec-path/v1"`, `unit_count`, then
`document_count`, `section_count`, `definition_count`, `block_count`, `table_count`, `clause_count`, and
`table_row_count`, followed by `[[unit]]` rows in document then source-tree pre-order, each with exactly
`unit_id`, `kind`, `document`, `section_ids`, `section_depths`, `section_ordinals`, `definition_id`,
`definition_ordinal`, `block_ordinal`, `block_kind`, `leaf_kind`, `leaf_ordinal`, `parent_unit_id`,
`content_sha256`, `normative`, and `ambiguous`. `specs/core-ownership.toml` has
`format = "msgriver/core-ownership/v1"`, `universe_sha256`, then one `[[ownership]]` row for every and
only leaf in universe order, each exactly `(unit_id, classification, rationale)` with a nonempty
trimmed rationale of at most 1,024 bytes. `specs/atomic-observables.toml` has
`format = "msgriver/atomic-observables/v1"`, `universe_sha256`, `ownership_sha256`, `complete`,
`observable_count`, then `[[observable]]` rows each exactly `(observable_id, unit_id, statement)` in
universe order, where `observable_id` matches `[A-Z][A-Z0-9_-]{2,63}` and is unique and `unit_id` is one
unique testable leaf after ownership validation. `complete = false` permits a bounded subset but forbids
any completeness claim; `complete = true` requires exact one-to-one testable-leaf equality. Unknown or
reordered fields, a count or hash mismatch, duplicate IDs, or duplicate unit aliases fail closed, and the
checker regenerates these exact bytes in memory before reading any downstream artifact.

Ownership classification values are closed: `core`, `layer:<protocol|store|connectors|client|server|
platform|tooling>`, or `context`, each with a required rationale. `layer:tooling` is a verification layer:
it owns repository-side specification parsing and linting, traceability generation and validation,
test/evidence conformance, build/CI verification, and release-gate machinery. It owns no daemon runtime
behavior, wire contract, durable state, connector action, client presentation, or host deployment
behavior; it is not a seventh shipping crate and not a new operation surface. Normative
verification/conformance leaves remain testable and may be assigned `layer:tooling`; they must not be
suppressed as `context` and must not be misassigned to pure domain `core`. `context` is admissible only
for units the extractor flagged `ambiguous` and never for `normative = true` units—those must be assigned
to a layer. The ownership catalog contains exactly one reviewed row per leaf, including all leaves of
A-10.2 allocator rules 1–22 and the named A-04.1, A-13.2, and A-15.3 categories; it makes
no completeness claim while any generated leaf lacks reviewed ownership.

Two boundary mutations govern the chain. W-1: delete one unnumbered `MUST` clause's unit from
`spec-universe.toml`, its observable, its ownership row, and its case, coherently renumber neighbours and
update every digest in artifacts 3–6, while leaving the canonical documents unchanged—the checker
regenerates `spec-universe.toml` from the unchanged canonical bytes, reproduces the deleted unit, and
fails `universe_regeneration_mismatch` before ownership or coverage equality is even evaluated. W-2: the
same deletion with the canonical clause also removed and `specs/release-identity.toml` updated fails the
release-identity digest check unless the manifest is changed, and any such manifest change is by
construction a reviewed maintainer action visible in the diff; per A-17.1, changing a digest is a reviewed
process action and is never semantic proof by hash. The closed extractor mutation obligations are named
gate obligations; each `UX-NN` below is required individually, and W-1 is required again as UX-15:

| ID | Mutation | Required result |
|---|---|---|
| UX-01 | both canonical bold-bullet forms present | recognized as `definition` (positive control) |
| UX-02 | heading depth promoted/demoted | `unit_id` changes for every descendant; stale references fail |
| UX-03 | unchanged clause relocated inside its section | `unit_id` changes; stale reference fails |
| UX-04 | one byte changed inside a clause | `unit_id` changes; stale reference fails |
| UX-05 | definition-shaped line inside a fence / HTML disguise / nested list / table cell | not a `definition`; existing A-17.1 disguise machinery applies unchanged |
| UX-06 | a case cites a `definition` or `section` id | rejected: composites earn no atomic coverage |
| UX-07 | a case cites an id absent from the regenerated universe | rejected `unknown_unit` |
| UX-08 | ownership row missing for one leaf | rejected `ownership_incomplete` |
| UX-09 | ownership row present for a nonexistent unit | rejected `ownership_extra` |
| UX-10 | a `normative` unit classified `context` | rejected `normative_context_forbidden` |
| UX-11 | duplicate `unit_id` (engineered collision attempt) | rejected `unit_identity_collision` before coverage |
| UX-12 | observable supplies `unit_ids = [u1, u2]`, a second unit field, a composite/container ID, a context leaf, or aliases a prior unit | rejected `observable_not_atomic`; exactly one unique scalar testable leaf is accepted |
| UX-13 | CRLF / trailing-whitespace change in a canonical document | release canonicalization normalizes line endings only; trailing horizontal whitespace changes `content_sha256` and fails |
| UX-14 | splitter fed an abbreviation-like `P-07.1.` / `AC-001. This …` | no spurious boundary; positive control |
| UX-15 | W-1 coherent derived-bundle deletion | rejected `universe_regeneration_mismatch` |
| UX-16 | multiline definition with lazy continuation, second paragraph, nested list/table/fence, then a sibling item | complete shared list-item span owns exactly its descendants; sibling is excluded |
| UX-17 | escaped/code-looking pipe, malformed separator, table in a list/quote, and a fence containing table text | extractor and spec checker consume identical shared table/row/cell spans; no private inference |
| UX-18 | soft break, multiple horizontal spaces, and markup around a boundary | clause count/text is stable under semantic folding while every source edit changes the containing content digest |
| UX-19 | paragraph/list/blockquote nesting and an intervening fence/table | exactly one leaf block per text region; one source-ordered ordinal sequence with no overlap or reuse |
| UX-20 | empty-vs-absent fields, chain concatenation, decimal-text, and kind-confusion codec aliases | distinct `PATH_V1` bytes; codec aliases rejected before hashing |
| UX-21 | five isolated fixture leaves containing `MUSTARD`, `MUSTard`, lowercase `must`, inline-code `MUST`, or autolink `MUST`, plus one isolated fixture leaf containing visible-prose `MUST NOT` | only the fixture's visible-prose `MUST NOT` leaf is normative; the other five fixture leaves are review-required ambiguous; `MUST NOT` is one longest-first keyword |
| UX-22 | second H1, unnumbered/foreign/duplicate heading, skipped depth, and closing ATX hashes | rejected before universe emission; valid depth pop updates all descendant paths |
| UX-23 | randomized map insertion/order, locale, timezone, and repeated generation | byte-identical canonical TOML and universe SHA-256 |
| UX-24 | any `clause` or `table_row` carries both flags or neither flag | rejected `universe_leaf_flag` before ownership validation |

### A-18.2. Generic HTTP/API promotion seam

The planned generic driver reuses typed provider catalog, fixed connector identity, secret references,
HTTP client policy, fenced outcomes, and operation protocol. Its future config decoder must compile a
closed declarative mapping into a non-Turing-complete internal plan at validation time. Runtime
execution receives only that plan and typed values; it cannot parse templates, choose a URL, load a
schema, or inspect arbitrary JSON paths.

Promotion requires its own threat model and complete RED matrix for path/query/body encoding, static
auth modes, OAuth token isolation, redirect/DNS/proxy/TLS behavior, response classification, secret
redaction, SSRF, resource expansion, and live provider evidence. Until then `generic_http_v1` is an
unknown/unsupported driver and no dormant general-purpose HTTP executor ships in the binary.

### A-18.3. Portability boundary

Core, store contracts, connector traits, and operation descriptors contain no systemd assumptions.
Platform adapters own peer credentials, UDS/file permissions, service notifications, disk probing,
and process hardening. A future Windows or macOS port must supply and test equivalent stable identity,
state locking, durable rename/fsync, secret storage, and local-admin transport; absence of an
equivalent fails closed rather than silently weakening the contract.

## A-19. Failure and recovery matrix

| Failure point | Client/operator result | Durable/recovery behavior |
|---|---|---|
| Before enqueue commit | Safe validation/unavailable error | No command or acceptance ID |
| After enqueue commit, before response | Connection may fail | Retry key returns the committed command |
| After prepare, before dispatch mark | No external effect claimed | Lease recovery may retry without duplicate flag |
| After dispatch mark, before known response | Ambiguous | Sticky possible-effect; bounded retry may mark duplicate risk |
| Outcome returned, fenced commit fails | Worker cannot claim result persisted | Readiness degrades; lease recovery arbitrates |
| Stale worker returns | No state rollback | Orphan evidence/late-ack rules only |
| Provider auth/config failure | Provider degraded/held | Shared bounded probe; healthy providers continue |
| SQLite/WAL/profile unsafe | Admission/effects fail loud | Reserved status/recovery; no early acknowledgement |
| Clock anomaly | Readiness degraded; prohibited work gets `clock_hold` | New effects and time terminals pause; fenced in-flight truth and safety cancellation still commit |
| Admission saturated after lost response | Existing result/conflict still available | Reserved pre-pass; miss rechecks atomically in admission |
| Credential/principal/mapping revoked | Later authentication fails closed | Mutation rechecks durable auth epoch before commit |
| Submit scope/provider grant removed | Fresh submit fails closed | Exact enabled-owner domain-key hit remains effect-free and recoverable |
| Backup job fails/cancels | Safe terminal job | Active DB unchanged; explicit staging file removed |
| Required recovery key absent | Restore names safe missing generation | No decrypt, staging activation, or guessed fallback |
| Restore upload/validation fails | Maintenance error | Active state unchanged; no provider process exists |
| Crash during generation activation | No automatic delivery | Atomic pointer names one complete generation or startup fails closed |
| Fixed-root branch serial exhausted | Readiness reports only `incarnation_exhausted`; allocating branch transitions return `state_incarnation_unavailable` | Nonallocating delivery/status/recovery/continuations remain available; recover through a new independently keyed blank root plus authenticated disaster restore, never in-place re-key |
| Upgrade prepare at fixed-root serial MAX | `state_incarnation_unavailable` before coordinator or hold | MAX−1 may prepare; rollback burns MAX exactly once and same-command recovery remains available at MAX |
| Upgrade prepare under pure clock hold plus nonterminal drain | `clock_hold` before drain, capacity, coordinator, or hold disclosure | Serial-headroom validation remains nonmutating; settlement preserves the original drain remainder |
| Upgrade prepare cannot fit complete exit capacity | `control_capacity` before fixed-root intent, coordinator, or hold | Exact-fit sum protects migrate, activation, dedicated rollback, rollback-mismatch divergence/repair, and the plan-bound journal format through one durable phase exit |
| Restored normal startup | Local recovery status available, effects/TCP held | Restored credentials suspended; fresh recovery actor required |
| Mutation during rollback-eligible upgrade smoke | `upgrade_activation_pending` | Selected state remains read-only; unexpected watermark drift fails closed |
| Upgrade rollback after activation/work | Rejected | Current generation retained; no accepted/effected work erased |
| CLI transport fails | Exit class 6, no guessed outcome | User can query/retry idempotently; CLI never opens service state |
| Telemetry sink fails | Rate-limited safe signal | Delivery follows configured degradation; no secret fallback |

## A-20. Architecture closure and references

This post-lens candidate has no intentionally deferred first-slice design decision. Numeric defaults
are configuration values inside compiled safety bounds and may be tuned only with the same tests. The
architecture-lens adjudication is `reviews/02-architecture-design/adjudication.md`; a blocker-closure
review must confirm these corrections before the RED suite freezes.

Primary implementation references:

- SQLite write-ahead log and durability behavior: <https://sqlite.org/wal.html>
- SQLite online-backup behavior and same-source-connection progress: <https://sqlite.org/backup.html>
- SQLite online-backup wrapper used by Rusqlite: <https://docs.rs/rusqlite/latest/rusqlite/backup/>
- Hyper HTTP/1 client bounds: <https://docs.rs/hyper/latest/hyper/client/conn/http1/struct.Builder.html>
- Rust standard-library file locking: <https://doc.rust-lang.org/std/fs/struct.File.html>
- Axum listener abstraction: <https://docs.rs/axum/latest/axum/serve/trait.Listener.html>
- ntfy publishing protocol: <https://docs.ntfy.sh/publish/>

## A-21. Planned Phase 0 provider ingress

Task 0176 invariants are represented below under distinct `P0-A0-*` identifiers, avoiding a second meaning for the accepted source identifiers.

| Accepted source ID | Planned living-architecture contract |
|---|---|
| P0-A0-001 (Task 0176 A0-001) | No callback-derived record commits before official authenticity verification. |
| P0-A0-002 (Task 0176 A0-002) | A callback is durably represented exactly once or returns retryable failure; acknowledgement never follows partial mutation. |
| P0-A0-003 (Task 0176 A0-003) | Callback ingress has no client/API-key authentication, CLI spelling, catalog entry, or callback-triggered external provider effect. |
| P0-A0-004 (Task 0176 A0-004) | Reply correlation uses only explicit provider reply context bound to an exact outbound provider-message identifier; phone, text, timing, caller correlation, and database search are forbidden. |
| P0-A0-005 (Task 0176 A0-005) | GET validates the bounded subscription mode and token before a bounded challenge without state; POST verifies one bounded raw byte sequence before parse/mutation, and public ingress/local ntfy disclose no body, destination, token, secret, raw callback, or maintenance address. |
| P0-A0-006 (Task 0176 A0-006) | Receipt/reply evidence is immutable and append-only, commits a reply-alert intent only for a new reply in the same transaction, and never changes historic v1 command state, uncertainty, or attempts. |
