# MsgRiver product specification

| Field | Value |
|---|---|
| Document status | Phase 0 product-plan revision |
| Product | MsgRiver |
| Specification version | 0.3.46 |
| Updated | 2026-09-19 |
| Owner | Evolutive Logic |

This is the living product contract for MsgRiver. It defines outcomes, boundaries, observable
behavior, and release claims. Implementation details belong in `specs/architecture.md`.

## P-00. How to read this specification

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative. Stable
identifiers make every requirement and acceptance scenario independently reviewable.

A behavior is not supported merely because an adapter or code path exists. MsgRiver claims support
only after automated contract tests and provider-specific live evidence are recorded.

### P-00.1. Support levels

| Level | Meaning |
|---|---|
| Contracted | Defined here and required of the product. |
| Implemented | Present in a released build and covered by hermetic tests. |
| Proven | Implemented and verified against a real provider or platform. |
| Planned | Directional intent only; clients MUST NOT depend on it. |

The first public release is not complete until all requirements explicitly marked **first slice** are
Implemented and the ntfy path is Proven on Linux.

Unless a requirement or capability is explicitly marked **Planned** or assigned to a later release,
every normative `PR-*` requirement and applicable `AC-*` scenario in this document is first-slice
scope. The release traceability matrix may not reclassify or omit one implicitly.

## P-01. Product intent

### P-01.1. Problem

Applications and infrastructure repeatedly rebuild the same unreliable outbound-notification glue:
credential loading, durable queuing, retry policy, provider error classification, redaction, status,
and operational recovery. Full engagement platforms solve a much larger problem and consequently own
recipient data, templates, preferences, campaigns, and user interfaces that do not belong in a small
infrastructure service.

### P-01.2. Promise

MsgRiver is a small, self-contained, single-node delivery service. It accepts an already-resolved
message command, persists it before acknowledging acceptance, and attempts delivery through an
operator-configured connector. It exposes honest status without pretending that provider acceptance
proves a human received or read the message.

### P-01.3. Primary outcomes

- **PR-001 — Durable handoff.** After MsgRiver acknowledges a command, process or host restart MUST
  NOT silently lose that command.
- **PR-002 — One integration surface.** Clients use one local/API and CLI contract while operators
  configure provider-specific connectors.
- **PR-003 — Operational honesty.** Status, retry, and duplicate semantics MUST describe what is
  actually knowable at each provider boundary.
- **PR-004 — Minimal ownership.** MsgRiver MUST NOT become a recipient directory, preference center,
  campaign manager, template studio, CRM, or general workflow engine.
- **PR-005 — Safe autonomy.** Applications may submit work without receiving provider credentials or
  choosing arbitrary network endpoints.
- **PR-006 — Inspectable operation.** A single operator can configure, run, diagnose, back up, drain,
  and recover MsgRiver without a separate broker, database server, or web console.

## P-02. Users and responsibilities

### P-02.1. Roles

| Role | Needs | Responsibilities |
|---|---|---|
| Client application | Submit a resolved message and inspect its status. | Own recipients, consent, preferences, content generation, and route choice. |
| Infrastructure client | Emit bounded operational notifications. | Avoid secrets in content and choose an approved connector/destination. |
| Operator | Configure connectors, limits, credentials, retention, and service lifecycle. | Authorize clients, protect host/network/state, monitor failures, and handle dead letters. |
| Maintainer | Evolve contracts and adapters. | Preserve compatibility, security boundaries, and evidence for support claims. |

### P-02.2. Ownership boundary

- **PR-020.** The client MUST resolve the recipient, preferences, consent, locale, final message
  content, registered provider, and provider-specific destination before submission.
- **PR-021.** MsgRiver MUST accept only the minimum destination snapshot needed for delivery and MUST
  NOT expose CRUD APIs for people, accounts, preference rules, subscriptions, or templates.
- **PR-022.** MsgRiver MAY retain delivery metadata and the minimum payload required for retry according
  to the configured retention policy; that retention does not transfer business ownership of the data.
- **PR-023.** One business notification sent through multiple channels is represented as independent
  message commands with distinct idempotency keys, conventionally derived from business event and
  channel/provider identity. Cross-channel policy and fallback remain client concerns until a future
  contract explicitly defines them.

## P-03. Scope and non-goals

### P-03.1. Contracted product scope

- Durable enqueue and status lookup.
- Idempotent command submission.
- Connector-specific validation before durable acceptance.
- Asynchronous delivery with bounded retry and explicit terminal outcomes.
- Dead-letter inspection and controlled replay.
- Cancellation and expiry where external effects have not begun.
- Operator-configured connectors and provider credentials.
- Auth-filtered discovery of the providers registered in the daemon and their safe capability schemas.
- Local CLI, local service interface, and an optional authenticated HTTP API.
- Health, readiness, metrics, structured redacted logs, backup, and recovery operations.
- Linux service operation first, with portable domain/store/connector boundaries.

### P-03.2. Explicit non-goals

- **NG-001.** Recipient profiles, address books, groups, preferences, consent, and unsubscribe flows.
- **NG-002.** Message authoring, templates, localization, campaigns, segmentation, or analytics.
- **NG-003.** An inbound chat, reply composer, conversation model, presence feature, or omnichannel inbox. The Planned Phase 0 WhatsApp reference loop records verified status/reply evidence and emits one safe local alert; it does not relax this boundary.
- **NG-004.** A workflow language, event bus, general job scheduler, or caller-directed arbitrary HTTP
  runner. An operator-registered generic message API/webhook provider is allowed; the caller still
  cannot select a URL, method, headers, authentication, or unvalidated request shape.
- **NG-005.** Exactly-once delivery, guaranteed ordering, or proof that a human read a message.
- **NG-006.** Caller-supplied provider base URLs, webhook URLs, request headers, or credentials.
- **NG-007.** A built-in web UI or hosted control plane.
- **NG-008.** Multi-node consensus or active-active operation in the first product line.
- **NG-009.** End-to-end content encryption managed by MsgRiver in the first slice.

## P-04. Macro product model

```text
client -- resolved message command --> MsgRiver -- provider request --> configured provider
   ^                                      |
   +---------- acceptance/status ---------+

operator -- config, credentials, policy --> MsgRiver
operator <-- health, metrics, redacted evidence -- MsgRiver
```

### P-04.1. Core concepts

| Concept | Definition |
|---|---|
| Message command | Immutable requested delivery: content, registered provider ID, destination, expiry, and idempotency identity. |
| Provider registration | Public, stable, operator-created delivery capability exposed to authorized clients with safe schemas and limits. |
| Connector | Private operator configuration binding one provider registration to a driver, endpoint, credentials, and policy. |
| Driver | MsgRiver implementation of a provider protocol, such as ntfy or SMTP. |
| Attempt | One invocation that may have crossed the external provider boundary. |
| Acceptance | Durable acceptance by MsgRiver, distinct from provider acceptance. |
| Provider accepted | Provider acknowledged the request; not evidence of device delivery or human receipt. |
| Dead letter | Terminally failed command retained under explicit policy for inspection or replay. |
| Principal | Stable client or operator identity used for ownership, authorization, limits, and idempotency; it exists independently of any one credential or operating-system session. |

### P-04.2. Responsibility boundaries

- **PR-040.** The service MUST persist an accepted command and its idempotency record atomically before
  returning success to the caller, and MUST cross the stable-storage barrier defined by P-07.1 first.
- **PR-041.** No provider network operation may be required to accept a valid command.
- **PR-042.** The connector endpoint and credentials MUST be operator-owned configuration. A command
  may select a registered provider ID but MUST NOT override its endpoint, credentials, TLS policy, proxy,
  or authentication headers.
- **PR-043.** Semantic request fields MUST be immutable after acceptance. Retention-driven redaction is
  an explicit recorded exception: it removes payload/destination availability but never rewrites what
  the command meant. Replay creates a new command linked to the old command.
- **PR-044.** Acceptance MUST bind the command to a non-secret connector identity snapshot: connector
  alias, driver kind/schema, normalized endpoint identity, TLS/egress policy, and destination-policy
  generation. Credential material MAY rotate for that same identity; queued work MUST NOT silently
  move to a different endpoint, driver, or destination policy.
- **PR-045.** The daemon MUST expose an authenticated, authorization-filtered provider catalog. A
  client sees only enabled provider registrations it may submit to.
- **PR-046.** Each catalog entry MUST include stable provider ID, display name, channel/driver kind,
  supported destination/content/options schema IDs and schema versions, safe effective limits,
  support level, and coarse availability. It MUST exclude endpoints, credential references, static
  headers, secret-bearing template fragments, filesystem paths, and unredacted operator diagnostics.
- **PR-047.** Catalog responses MUST carry a deterministic generation/ETag so clients can cache and
  detect configuration changes. Submission is always validated against the current registration and
  then pinned under PR-044; catalog discovery is informative, never a TOCTOU authorization grant.
- **PR-048.** Drivers MUST publish machine-readable closed schemas for every exposed destination,
  content, and options kind. The daemon returns these schemas or stable references in the catalog so a
  CLI, application, or future UI can construct valid requests without provider-specific guesswork.

## P-05. Capabilities and release plan

### P-05.1. First slice

The first slice is production-shaped rather than a disposable prototype. It MUST include:

- one portable Rust distribution containing the daemon composition root and an API-only CLI client on
  Linux; the client package MUST NOT depend on the SQLite/store package;
- a durable single-node SQLite queue;
- ntfy connector configuration and delivery;
- a deterministic fake connector used only by tests;
- a versioned HTTP-shaped protocol over a Unix-domain socket, with filesystem access as the first gate
  and stable principals/scopes supplied by peer mapping or API credentials;
- an optional TCP binding where every request, including loopback, is authenticated; non-loopback use
  additionally requires a documented trusted TLS reverse proxy or native TLS;
- local principal and API-key create/list/rotate/revoke operations with one-time secret display;
- versioned HTTP endpoints and corresponding CLI commands for every client and operator capability,
  including submit, status, cancel, dead letters, replay, health, readiness, admission state,
  configuration validation/activation, principals, peer mappings, credentials, key rings, audit,
  drain, upgrade state, consistent backup, restore, and retained-generation cleanup;
- idempotency, leases, crash recovery, bounded retry, expiry, overload protection, and graceful
  shutdown, held restore, and explicit post-restore resume;
- redacted structured logs and low-cardinality metrics;
- validated-restart configuration changes (no live reload in this slice), systemd packaging, rollback
  documentation, and a real ntfy smoke on Sol.

### P-05.2. Provider roadmap

| Channel/protocol | Status at bootstrap | Planned destination supplied by client | Operator-owned configuration |
|---|---|---|---|
| ntfy | First-slice Proven target | Topic name | Base URL, credentials, limits |
| SMTP email | Planned | Validated mailbox address | Server, TLS/auth, sender identities |
| WhatsApp Cloud API | Phase 0 Planned reference loop | Closed E.164 recipient plus approved template/locale/typed parameter data | Meta account, sender, token, fixed endpoint, verification/app secrets, template allowlist and limits |
| SMS | Planned | E.164 recipient | Provider account, sender, credentials, endpoint |
| Microsoft Teams | Planned | Route alias or allowed channel identifier | Webhook/API target and credentials |
| Slack | Planned | Route alias or allowed channel identifier | Webhook/API target and credentials |
| Generic HTTP API/webhook | Planned | Values conforming to the registered closed destination/content/options schemas | Fixed endpoint/method/auth/static headers, declarative request mapping, response classification |

Planned rows are not compatibility promises. Each driver requires its own threat model, validation
contract, error taxonomy, hermetic conformance suite, and live evidence before promotion.

### P-05.3. Planned generic message API/webhook driver

The Planned Phase 0 reference loop is one official WhatsApp sender plus existing local ntfy: it uses verified/deduplicated callback ingress, exact-context-only reply correlation, immutable receipt/reply evidence, bounded local retention, and one safe ntfy alert; its complete product and architecture sources are Tasks 0175 and 0176, and it remains neither an inbox nor a public support claim. The generic driver is a planned provider-registration type, not first-slice Implemented support. Its
purpose is broad integration with common outbound message APIs without adding one Rust driver per
service. Before promotion to Implemented it MUST support a bounded declarative subset of:

- fixed operator-owned HTTP `POST`, `PUT`, or `PATCH` endpoints;
- JSON, form-encoded, and conventional webhook request profiles;
- operator-defined closed input schemas and deterministic JSON/form/path-segment/query-value mappings;
- static headers and authentication selected from no-auth, bearer, basic, API-key header, and OAuth2
  client-credentials profiles, with all secret values operator-injected;
- explicit success status sets, default HTTP error taxonomy, bounded `Retry-After`, and optional safe
  response-field extraction through declared JSON pointers;
- the same timeout, redirect, TLS, proxy, response-bound, redaction, retry, idempotency, and circuit
  contracts as native drivers.

It MUST NOT accept caller-supplied URLs, methods, header names/values, credentials, template source,
JSON pointers, scripts, arbitrary expressions, or raw provider bodies. Placeholders are typed values
from the registered schema and are encoded according to their declared destination; they can never
alter scheme, authority, or path structure. The catalog exposes the client-facing schema, never the
operator's request template or secrets.


### P-05.4. Planned Phase 0 WhatsApp evidence loop

The following Task 0175 requirements are Planned, individually represented source contracts; they authorize neither provider support nor an implementation.

| Accepted source ID | Planned living-spec contract |
|---|---|
| P0R-001 | Retain local ntfy and add only one operator-configured official WhatsApp Business Cloud sender; callers select a registered capability and never supply a provider endpoint, token, sender identifier, webhook, header, or arbitrary body. |
| P0R-002 | A send uses an approved registered template with bounded versioned parameters and rejects unsupported shape, destination, locale, or count before acceptance; it never translates, splits, or falls back to free-form text. |
| P0R-003 | The reference loop is durable acceptance, official request, status callback, reply callback, verification/deduplication, immutable lifecycle evidence, one reply alert, and authorized safe inspection. |
| P0R-004 | Inbound reply handling is receive-and-alert only: it never composes, sends, or triggers an outbound WhatsApp response. |
| P0R-010 | GET and POST authenticate through the official mechanism before mutation; POST verifies bounded raw bytes with bounded syntax/algorithm validation and constant-time comparison, and secrets never reach clients, ntfy, exports, metrics, or routine logs. |
| P0R-011 | The ingress bounds body, content type, depth, and deadline before parse; invalid, unsigned, or malformed callbacks mutate no message, reply, or alert state and disclose no raw payload. |
| P0R-012 | A valid callback crosses one durable barrier for deduplication, provenance, immutable evidence, and any required reply-alert intent; pre-barrier failure is retryable and ntfy dispatch is out of band. |
| P0R-013 | Deduplication uses a stable provider identity or a documented versioned fingerprint of verified immutable fields, fails closed otherwise, and retains an explicit window no shorter than the documented provider replay window. |
| P0R-014 | A duplicate returns the same safe acknowledgement with no second event or alert intent, remains duplicate evidence, and preserves that result across restart. |
| P0R-020 | Provider acceptance, delivery/read/failure status, and verified reply are distinct immutable evidence and never prove a broader human outcome. |
| P0R-021 | Historic v1 `provider_accepted` remains terminal; the append-only receipt/reply stream never rewrites state, uncertainty, attempt, or transition history. |
| P0R-022 | Status links only through the exact durable provider-message binding; replies link only through explicit provider reply context, while missing, stale, unknown, or ambiguous context remains unmatched without heuristics. |
| P0R-023 | Every reply is an independent event with verification, correlation, safe reference, and retention state, never a participant profile, conversation, presence, read UI, or inbox. |
| P0R-024 | The WhatsApp customer-service window is advisory evidence only (active, unknown, or expired), never permission for an unapproved template or proof of consent. |
| P0R-030 | One verified unique reply creates one durable local ntfy intent containing only safe event reference, match disposition, and safe timestamp. |
| P0R-031 | Authorized local inspection/export is safe by default; raw reply access is local-only, defaults to 24 hours, may be zero, never exceeds seven days, and preserves only safe integrity evidence after purge. |
| P0R-032 | Evidence is append-only; correction adds a disposition and payload purge is the sole recorded removal. |
| P0R-040 | The future reference deployment is one Sol operator, one official account/sender/template, HTTPS ingress, and local ntfy, with credentials provisioned outside Git. |
| P0R-041 | The future runbook covers activation, proxy, rotation, replay/recovery, drain, backup/restore, rollback, and ntfy-independent inspection without public maintenance exposure. |

## P-06. Message command contract

### P-06.1. Required semantic fields

Every command MUST contain:

- `idempotency_key`: caller-generated opaque key within the authenticated principal's scope;
- `provider`: an operator-defined registered provider ID;
- `destination`: a provider-specific, bounded object with explicit `kind` and `schema_version`;
- `content`: an already-resolved, bounded object with explicit `kind` and `schema_version` supported by
  that connector;
- optional `options`: provider-specific bounded delivery controls with explicit `kind` and
  `schema_version`; absence selects the connector's documented defaults;
- optional `expires_at`: absolute UTC instant after which a new attempt MUST NOT begin;
- optional `correlation_id`: opaque caller reference meeting the safe identifier grammar.

The HTTP path is the sole public API-version signal; a body-level `api_version` field is rejected.
MsgRiver generates the globally unique `message_id`, creation timestamp, attempt identities, and
status history. A `message_id` is non-secret and safe to log but MUST NOT be treated as an
authorization capability. Idempotency and correlation identifiers MUST match
`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`; they are never metric labels or routine log fields.

### P-06.2. Content baseline

- **PR-060.** The common baseline is `content.kind = "text"`, `schema_version = 1`, containing UTF-8
  plain text with an optional short title. Drivers MAY expose additional discriminated, versioned,
  schema-validated content and destination kinds. A typed extension has a published closed schema,
  canonicalization, size limits, and compatibility rules; it is never arbitrary provider JSON,
  headers, endpoints, credentials, or an unvalidated property bag.
- **PR-061.** Validation MUST happen before acceptance for provider registration, destination shape, content
  type, byte length, title length, expiry bounds, identifier grammar, and unknown fields.
  The identifier grammar length ceiling is 128 characters, and an identifier of exactly 128 characters that
  otherwise satisfies the grammar MUST be accepted. An empty identifier MUST be rejected before acceptance
  with the stable error class `invalid_identifier`. An identifier longer than 128 characters MUST be rejected
  before acceptance with the stable error class `invalid_identifier`. An identifier whose first character is
  `.` MUST be rejected before acceptance with the stable error class `invalid_identifier`. An identifier
  containing any non-ASCII character MUST be rejected before acceptance with the stable error class
  `invalid_identifier`.
- **PR-062.** Invalid UTF-8, control-character misuse, unsupported formatting, and a past expiry or an expiry at or before the current accepted clock observation MUST
  be rejected without creating a command. For decoded `text/1` Unicode scalar values, control-character
  misuse means `U+0000..=U+0008`, `U+000B..=U+000C`, `U+000E..=U+001F`, or
  `U+007F..=U+009F` in the body; HT (`U+0009`), LF (`U+000A`), and CR (`U+000D`)
  remain body text and preserve their exact bytes. An optional title rejects every scalar in
  `U+0000..=U+001F` or `U+007F..=U+009F`. A body-only control rejection has stable class
  `invalid_text_control`; a title control rejection has stable class `invalid_title_control`.
  This rule does not select precedence among simultaneous invalid conditions or alter the
  existing non-default-profile boundary.
- **PR-063.** The default and compiled first-slice ceiling for the serialized command is 64 KiB, the
  title ceiling is 256 UTF-8 bytes, and the common text schema ceiling is 60 KiB. These are global
  envelope/schema ceilings, not promises that every provider accepts them. Each provider catalog MUST
  advertise an equal or lower effective limit and submission MUST enforce that lower value; native
  ntfy is 4,096 text bytes. Operators MAY lower these limits; raising a compiled ceiling requires an
  explicit release change.
- **PR-064.** MsgRiver MUST NOT silently truncate, translate, reformat, split, or downgrade content.
  Provider constraints produce a validation or terminal error with a stable error class.

### P-06.3. ntfy destination and content

For the first-slice ntfy driver:

- An ntfy destination MUST use `destination.kind = "ntfy_topic"` and `destination.schema_version = 1`;
- an ntfy destination MUST contain `topic`;
- `topic` MUST match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`; path/query/fragment delimiters, dot segments,
  percent encoding, control characters, and non-ASCII confusables are therefore impossible;
- ntfy text content MUST use `content.kind = "text"` and `content.schema_version = 1`;
- ntfy text content MUST supply the required `text` field as UTF-8 plain text defined by P-06.2;
- ntfy text content MAY supply the optional short title defined by P-06.2;
- supplied ntfy options MUST use `options.kind = "ntfy"` and `options.schema_version = 1`;
- ntfy options schema v1 MAY supply `priority`;
- when supplied for ntfy options schema v1, `priority` MUST be one of `min`, `low`, `default`, `high`,
  or `max`;
- ntfy options schema v1 MAY supply `tags`;
- when supplied for ntfy options schema v1, the `tags` list MUST contain at most eight entries;
- every tag supplied for ntfy options schema v1 MUST match `^[A-Za-z0-9][A-Za-z0-9_+-]{0,31}$`;
- the first-slice ntfy contract MUST NOT accept caller-supplied click URLs, attachment URLs, action
  URLs, custom headers, or authentication data because they expand egress and injection boundaries;
- the final request URL MUST be derived exclusively from the configured base URL and validated topic;
- the connector contract MUST assert the canonical method and URL byte-for-byte.

## P-07. Acceptance, identity, and idempotency

### P-07.1. Durability contract and crash model

An accepted command MUST survive:

1. abrupt process termination, including `SIGKILL`;
2. operating-system crash or host power loss after the acceptance response, when the documented
   filesystem and block device truthfully honor successful stable-storage barriers; and
3. ordinary restart or upgrade under the supported migration procedure.

MsgRiver does not claim survival of lying volatile device caches, filesystem or media corruption,
loss of the only state device, malicious state modification, or disasters outside the operator's
backup recovery-point objective. Those failures must be detected where possible and MUST NOT be
misreported as successful local durability or zero-RPO disaster recovery.

Acknowledgement MUST occur only after the command, principal ownership, canonicalization version,
idempotency mapping, and initial status cross the applicable stable-storage barrier atomically. Group
commit is permitted only when every grouped caller waits for the same successful barrier. Throughput
or latency configuration MUST NOT weaken this contract.

- **PR-070.** A successful submit response means “durably accepted by MsgRiver,” not delivered.
- **PR-071.** Idempotency scope is `(principal_id, idempotency_key)`. Connector or destination MUST NOT
  silently change that scope. A stable principal survives credential rotation and service restart.
- **PR-072.** Repeating a command with the same canonical semantic fingerprint within the idempotency
  window MUST return the original `message_id`, current state, `deduplicated = true`, and
  `idempotency_expires_at`, and MUST NOT enqueue another delivery. This applies to every prior state;
  it is never presented as fresh acceptance. An existing-result lookup requires a currently valid
  authentication for the exact enabled owner principal, but does not require that principal to retain
  the submit scope or provider grant needed for a fresh command because it creates no new effect.
  A revoked/expired credential or disabled principal cannot authenticate and receives no result.
  Deliberate resend/replay requires a new idempotency key.
- **PR-073.** Reusing the key with a different semantic command MUST return an idempotency conflict and
  MUST preserve the original command.
- **PR-074.** Equality is based on a canonical semantic fingerprint, not raw JSON member ordering or
  irrelevant transport formatting. The persisted canonicalization version and keyed fingerprint MUST
  cover every semantic request field. The fingerprint is sensitive metadata: it uses a service-held
  keyed MAC, and old MAC keys remain available until every covered idempotency window expires. MAC key
  identity is branch-safe and bounded: it is a structured origin-plus-serial value that survives
  branching and artifact closure rather than a counter reset on restore/rollback, and the retained key
  ring per purpose is bounded so lookup work is independent of rotation history.
  The v1 canonical request form MUST be the fixed-field-order, u32 big-endian length-prefixed byte encoding
  of the semantic request fields, prefixed by the `msgriver-request` domain tag and canonicalization version
  `0x0001`, with absent optional members (`options`, `expires`, `correlation`) encoded as explicit absence
  markers rather than omitted. The semantic request fingerprint MUST be a domain-separated HMAC-SHA256 keyed
  MAC over the v1 canonical bytes, computed with the active service-held MAC key and its key version, so the
  tag is bound to the semantic-request purpose; the active MAC key version MUST participate as an input of the
  fingerprint computation, so every issued tag carries its originating key version and tags across key rotations
  remain distinguishable. The lookup digest over the (authenticated principal, command key) pair MUST be a keyed
  MAC computed under a purpose domain distinct from the semantic-request fingerprint domain, so a lookup digest
  is never equal to or interchangeable with a semantic fingerprint.
- **PR-075.** The configured idempotency window MUST be explicit, MUST default to seven days, and MUST
  use a half-open interval ending at the returned `idempotency_expires_at`. Evidence retention MUST be
  at least as long as the window; invalid combinations fail configuration validation. At or after the
  exact expiry instant, the same key is eligible to identify a new command and may cause a new effect.
  Expiry authority is monotonic: an idempotency result/conflict once proven expired by PR-149's durable
  authenticated safe-time high-water MUST never become visible or reserved again after a later clock
  anomaly, restart, or generation selection whose authenticated inputs include that proof. A hold may
  leave a not-yet-proven comparison provisionally unexpired while every fresh effect is blocked; it
  cannot revive proven-expired truth.
- **PR-076.** If persistence is unavailable, full, corrupt, or cannot meet its durability contract,
  submit MUST fail loudly and MUST NOT claim acceptance.
- **PR-077.** Concurrent equivalent submissions for one scope/key MUST serialize to one command and
  return the same result. Concurrent conflicting submissions create at most one command; all others
  receive conflict. An already-existing idempotency lookup remains available when new admission is
  closed or fresh-operation authorization has been removed, subject to the authenticated-owner rule
  in PR-072 and control-plane reserves.

## P-08. Delivery semantics and lifecycle

### P-08.1. Public states

| State | Terminal | Meaning |
|---|---:|---|
| `queued` | No | Accepted and awaiting an eligible attempt. |
| `held` | No | Attempts are blocked by an explicit safety/connector condition; `hold_reason` identifies it and expiry still applies. |
| `delivering` | No | Leased to a worker; a provider effect may be in progress. |
| `retry_scheduled` | No | Prior attempt failed transiently or ambiguously; next attempt is delayed. |
| `provider_accepted` | Yes | At least one provider acknowledgement is known. Human/device receipt is unknown. |
| `failed` | Yes | Policy ended attempts without a known provider acknowledgement; an effect may still have occurred. |
| `cancelled` | Yes | Cancellation prevented every further attempt; prior in-flight/ambiguous effects remain disclosed. |
| `expired` | Yes | Expiry prevented every further attempt; prior in-flight/ambiguous effects remain disclosed. |

Every status response MUST include the state, `message_id`, creation/update instants, attempt count,
`effect_may_have_occurred`, `duplicate_effect_possible`, and a safe stable outcome/error class where
applicable. Once uncertainty or duplicate possibility becomes true, it is sticky across retries and
terminal transitions. Safe attempt history records known acknowledgement, ambiguity, fence, and
configuration generation without provider bodies or secrets. Content and destination disclosure
requires explicit authorization and is disabled from ordinary list output.

`provider_accepted` is terminal in public API v1. Asynchronous bounces, delivery/read receipts, and
post-acceptance provider feedback are outside the v1 state contract; the Planned Phase 0 WhatsApp
reference contract records them only in a separate immutable evidence stream and MUST NOT reinterpret
a historical v1 terminal state.
Matching verifiable provider acceptance for an attempt that already exists in retained evidence is
different: it corrects the command to truth already caused by that v1 attempt. It is the sole permitted
terminal-to-terminal promotion, from `failed`, `cancelled`, or `expired` to the absorbing
`provider_accepted` state. It creates no attempt, erases no later history or uncertainty, and cannot be
triggered by an unmatched, unverifiable, ambiguous, or non-acceptance callback.

### P-08.2. Attempt rules

- **PR-080.** Delivery is **at least once**. A duplicate provider effect is possible after an ambiguous
  timeout, crash, or lost acknowledgement. MsgRiver MUST document and expose ambiguity; it MUST NOT
  claim exactly once.
  A `queued` command claimed through `fair_claim` MUST enter `delivering`, and that claim MUST leave
  `cancel_requested`, effect-may-have-occurred, and duplicate evidence unchanged. A `fair_claim` against a row
  already in absorbing `provider_accepted` MUST be rejected with class `invalid_transition` and MUST NOT change
  the row's state or evidence. Effect-may-have-occurred evidence, once true, MUST NOT be cleared by any later
  outcome; in particular a transient outcome committed from `delivering` with that evidence set MUST move the row
  to `retry_scheduled` with the evidence still true and `cancel_requested` and duplicate evidence unchanged.
- **PR-081.** A worker MUST hold a current lease/fence before starting an attempt. Expired work becomes
  recoverable without requiring process memory. Outcome commits MUST compare-and-swap the same fence.
  A stale non-acceptance cannot change current state; stale ambiguity remains sticky evidence; a late
  verifiable provider acknowledgement for matching retained attempt evidence MUST promote an ordinary-held,
  `retry_jitter_unavailable`-held, clock-held, or upgrade-held non-accepted row—and, among terminal
  rows, MUST promote only `failed`, `cancelled`, or `expired`—to absorbing `provider_accepted` without
  erasing newer attempt history. No other late
  outcome changes a terminal row. Lease duration MUST exceed connector timeout plus a bounded result-
  commit margin, and invalid configurations fail before readiness.
  An ambiguous outcome committed under a stale lease or fence MUST be arbitrated as stale, MUST OR its ambiguity
  into the row's existing sticky evidence rather than replace it, and MUST NOT change the row's attempt count.
- **PR-082.** No database transaction may remain open across provider network I/O.
- **PR-083.** Provider outcomes MUST be classified as accepted, transient, rate-limited, permanent,
  authentication/configuration, or ambiguous. Unknown outcomes default to ambiguous with bounded
  retry. A driver may fail closed only when its published threat model proves why duplicate risk
  outweighs loss risk; the deviation is visible in configuration and connector health.
- **PR-084.** Retry uses operator-bounded exponential backoff with jitter. A valid provider
  `Retry-After` MAY extend the delay within configured bounds. The multiplier MUST be derived deterministically by
  the host-side `JitterSource` from `(derivation_version, RetryJitterV1 MacKeyRef, MessageId UUIDv7 bytes,
  completed_attempt_ordinal)`, represented as a fixed-point value in milli units, and MUST lie in `[500, 1500]`
  milli. Absent a stricter effective `clock_anomaly` or `upgrade_quiescing` deferred-projection hold under
  PR-087, an unavailable or exhausted source MUST retain the fenced provider outcome in nonterminal
  `held(retry_jitter_unavailable)` with no retry deadline or provider effect; it MUST NOT use a fallback key,
  constant, or biased mapping. When a valid provider `Retry-After` is honored at the
  connector boundary, the effective delay MUST combine as `max(scheduled backoff, Retry-After)` within configured
  bounds. A valid provider `Retry-After` above the configured ceiling MUST be clamped to the ceiling and then
  combined as `max(scheduled backoff, clamped Retry-After)`.
- **PR-085.** Permanent validation failures MUST NOT be retried. Authentication/configuration failures
  MUST surface connector health, enter a persisted connector-wide cooldown/circuit state, and use
  bounded probes rather than one probe per queued message. If upgrade quiescence defers safe-time
  projection, connector health MUST expose bounded `quiescing_deferred` truth immediately; the one
  shared circuit record and probe deadline are then persisted atomically with the hold-clear projection,
  never fabricated per held message.
- **PR-086.** The service MUST impose maximum attempts and maximum elapsed delivery age. Exhaustion
  transitions to `failed` and creates dead-letter evidence according to retention policy.
- **PR-087.** Before each new attempt, MsgRiver MUST enforce expiry and cancellation. Cancellation
  cannot recall an invocation already started or a message already accepted by a provider. A cancel
  during `delivering` records `cancel_requested`. Outcome projection has one total order: known provider
  acceptance wins; otherwise a committed cancellation request wins; absent cancellation, crossed
  expiry or maximum delivery age wins; then attempt exhaustion; only then does permanent, retryable,
  authentication/configuration, or ambiguous classification choose the ordinary next state. Ambiguity
  remains sticky under cancellation, expiry, or exhaustion. A decisive guard present when the fenced
  outcome commits terminalizes in that transaction. A guard committed after an `upgrade_quiescing`
  hold is retained there and resolved only by that hold's projection. `clock_anomaly`,
  `upgrade_quiescing`, and `retry_jitter_unavailable` are deferred-projection holds, never ordinary
  holds: generic hold-clear cannot release them. Clock and upgrade quiescence are stricter and win the
  initial hold label over a concurrently unavailable jitter source; their sole projection derives jitter
  through the already persisted key reference and moves to `retry_jitter_unavailable` if that source is
  still unavailable. Cancellation and expiry/max-age terminalize a `retry_jitter_unavailable` hold under
  this same precedence, while they remain retained guards for an upgrade-quiescing hold. Safe status exposes
  `cancel_requested` immediately so a caller can distinguish a committed cancellation request while
  delivery resolves. Cancelling a terminal command is an
  idempotent no-op returning its current state. Cancellation remains available during a clock hold as
  a safety-reducing mutation: queued/held/retry work becomes `cancelled`, while delivering work records
  `cancel_requested`; it cannot release a lease, schedule a retry, or cause a provider invocation.
  When attempt exhaustion is the winning rung of the outcome projection order (no known provider acceptance,
  no committed cancellation request, no crossed expiry or maximum delivery age, and no late verifiable
  acknowledgement), the resulting terminal state MUST be `failed`.
- **PR-088.** MsgRiver makes no global or per-destination ordering guarantee. Concurrency and retry may
  reorder effects; clients requiring order must wait for a terminal status before submitting the next
  dependent command.

## P-09. Capacity, backpressure, and fairness

- **PR-090.** Operators MUST have bounded global, per-principal, and per-connector message/byte/rate
  admission limits plus worker, request, connector-concurrency, and retry limits. Defaults reserve
  capacity for at least one healthy principal/connector and remain safe within the published minimum
  host profile.
- **PR-091.** When an admission limit is reached, new submissions MUST be rejected before acceptance
  with a retryable overload response. Already accepted work remains durable.
- **PR-092.** Status, existing-idempotency lookup, and operator recovery operations MUST remain
  available within a dedicated control-plane reserve while new admission is
  closed, including during provider outage or queue saturation.
- **PR-093.** One unhealthy connector MUST NOT consume all worker capacity or starve healthy
  connectors. The configured scheduler bound and acceptance evidence MUST quantify the maximum healthy
  connector wait under the reference fault workload.
- **PR-094.** Retry storms MUST be damped with jitter, connector-level concurrency/rate limits, a
  persisted shared cooldown/circuit, bounded recovery ramp, and bounded probes for configuration or
  authentication failures.
- **PR-095.** Storage reserve thresholds MUST stop admission before SQLite or the host filesystem is
  exhausted. Admission accounting is byte-aware and reserves bounded space for WAL/checkpoint growth,
  lease/outcome writes, terminal transitions, purge, status/recovery operations, and one configured
  backup. Crossing a critical threshold degrades readiness, pauses effects if their result cannot be
  recorded safely, and emits an operator signal.

### P-09.1. First-slice capacity target

On the documented Sol-class reference host, with 4 KiB fake-provider messages and durability enabled,
the release candidate MUST demonstrate, without weakening P-07.1:

- 50 accepted submissions per second for ten minutes;
- a burst of 500 submissions without loss;
- 100,000 queued messages within configured disk bounds;
- local submit p95 below 100 ms under the sustained test;
- recovery after forced termination with no acknowledged command missing.

Benchmark evidence records CPU, memory, storage device/filesystem, mount options, SQLite durability
settings, reserve configuration, binary revision, and command. These are a release regression floor on
the named reference host, not a universal SLA.

## P-10. Authentication and authorization

### P-10.1. Local access

- **PR-100.** The default service interface is a Unix-domain socket whose ownership and mode are the
  first access gate. An accepted connection maps to a stable principal and scopes through a validated
  peer-UID mapping or an API credential; caller-provided identity headers are never trusted. Peer
  mappings are durable service state and their complete lifecycle is available through the local
  versioned API and CLI; they are never a hidden root-file-only control. Every selected state MUST
  retain at least one enabled UID-0 normal-UDS mapping whose enabled principal and mapping ceiling both
  include `operator`. A principal or mapping mutation whose prospective state would remove the last such
  local recovery path MUST fail atomically with stable `last_local_operator`; a replacement is created
  before the predecessor can be disabled, descoped, remapped, or deleted.
- **PR-101.** Multiple peer UIDs MAY deliberately map to one shared principal, but then they share
  ownership, quotas, status visibility, and idempotency namespace. Applications needing isolation use
  separate principal mappings or scoped credentials. Filesystem group membership alone never grants
  operator scope.
- **PR-102.** Administrative operations MUST require an operator scope and MUST NOT be exposed merely
  because a client can submit.

### P-10.2. TCP access

- **PR-103.** TCP listening is disabled by default. Loopback TCP MAY be enabled for a local reverse
  proxy or smoke tooling, but every TCP request, including loopback, MUST authenticate. Loopback address
  location is not an authorization mechanism.
- **PR-104.** Non-loopback exposure MUST be an explicit configuration, MUST use authenticated
  principals, and MUST be protected by TLS at MsgRiver or a documented trusted reverse proxy.
- **PR-105.** API keys bind to a stable named principal rather than becoming that principal. Each key
  contains a public lookup identifier and at least 256 random secret bits, is displayed once, and is
  stored only as a constant-time keyed verifier using a service pepper outside the database. Keys are
  independently listable by safe metadata, rotatable, revocable, scoped, rate-limited, and never
  logged. Rotation preserves message ownership and idempotency scope.
- **PR-106.** Required scopes are `submit`, `status:own`, `cancel:own`, and `operator`; `operator`
  includes the others. A `message_id` is never a capability. A non-owner lookup/cancel returns the same
  safe not-found response as an unknown ID, with internal audit evidence but no existence disclosure.
- **PR-107.** Authentication failures and rate limits MUST be observable without recording presented
  secrets or destination/content data. Header acquisition and public-ID classification have separate
  bounded concurrency, byte, and timeout limits; traffic that has not completed classification cannot
  enter the verifier scheduler. Invalid-authentication abuse is isolated by bounded per-source buckets
  and a global abuse budget, while a separately reserved verification lane for a syntactically valid
  ID currently present in the published enabled-key index cannot be consumed by unknown-ID traffic.
  Once a complete bounded header has been classified, one attacked known public key ID may lease at
  most one verifier globally, independent of source count, and cannot prevent a different known ID from
  completing authentication within 250 ms under the deterministic reference workload. Unknown IDs
  still receive dummy work and all verifier comparisons remain constant-time. A distributed slow-
  header flood or simultaneous attack across many distinct enabled public IDs MAY exhaust a bounded
  ingress/queue and receive a uniform retryable rejection; v1 makes no valid-principal latency claim
  for those explicitly excluded denial-of-service workloads. Source address is defense-in-depth, not
  an identity or the sole fairness key.
- **PR-108.** On UDS without a bearer credential, effective authorization is the intersection of the
  mapped principal's current scopes and its peer-mapping ceiling. On UDS with a bearer credential, an
  invalid credential MUST fail without peer fallback; a valid credential MUST name the same principal
  as the peer mapping, and effective authorization is the intersection of principal, key, and peer
  scopes. On TCP it is the intersection of principal and key scopes. Revocation MUST be effective for
  every request authenticated after its durable commit.

### P-10.3. Operation authorization matrix

This grouped table is the human-readable policy summary. The release lint independently freezes the
authorization profile, complete binding set, idempotency class, and risk class for every one of the 70
catalog operation IDs; adding, removing, or swapping any assignment is a specification failure.

| Operation | Minimum authorization |
|---|---|
| Health/readiness probe | Enabled normal-UDS peer with any effective scope, UID-0 maintenance peer, or authenticated TCP principal/key with any nonempty effective scope; no sensitive detail |
| Discover allowed provider registrations/schemas | Any authenticated principal with `submit` or `status:own`, filtered by provider authorization |
| Submit | `submit` |
| Get/list safe own status and attempts | `status:own` plus owner match |
| Cancel own non-terminal command | `cancel:own` plus owner match |
| List all queue/dead letters/attempts | `operator` |
| Cancel another principal's command | `operator` |
| Reversible admission open/close and bounded drain | `operator` |
| Replay and purge payload | `operator` over the normal local Unix admin API only |
| Clock status and exact-observation acknowledgement | `operator` over the normal local Unix admin API, or the state-owner peer over the maintenance Unix API; acknowledgement remains available during clock hold |
| Resume restored delivery | Fresh restore-specific local recovery operator plus the exact report acknowledgements |
| Metrics | `operator`, or a dedicated local-only metrics binding |
| Principal/API-key/peer-mapping/grant administration | `operator` over the local Unix admin API only |
| Audit, upgrade preparation, and consistent backup | `operator` over the normal local Unix admin API only |
| Config export/validation and upgrade status | `operator` over the normal local Unix admin API, or the state-owner peer over the maintenance Unix API |
| Config activation, state/recovery key lifecycle, migration, restore/bootstrap, generation cleanup | State-owner operating-system authorization through maintenance-mode Unix API |
| Graceful shutdown | `operator` over the normal local Unix admin API, or the state-owner peer over the maintenance Unix API |

The first operator is bootstrapped through the maintenance listener while the normal delivery daemon
is stopped. Subsequent principal/key operations use the local operator channel. Every allow/deny cell
is a conformance-test case.

- **PR-109.** Every catalog operation classified `command_key` or `one_time_secret` MUST have one
  durable command record scoped by operation ID and the authenticated stable actor namespace. It stores
  only a purpose-separated keyed command digest/version, purpose-separated keyed semantic request or
  explicitly allowed phase fingerprints, phase, safe stable result, source runtime/process identity,
  and terminal retention;
  the raw key and secret output are never retained. A terminal-safe command receives an exact half-open
  `command_expires_at` using the configured PR-075 duration, which defaults to seven days. A command
  still carrying an authoritative continuation, including unacknowledged recovery escrow, reports a
  null expiry and cannot age out; terminal acknowledgement or separately keyed retirement starts its
  retention window. Same-actor/same-operation/same-key compatible retry returns the existing
  phase/result, incompatible body/phase conflicts, and no effect is repeated. Current authentication
  and the operation's current authorization are rechecked before disclosing a `command_key` or
  `one_time_secret` result; PR-072 separately governs effect-free owner recovery for `domain_key`.
  The record commits atomically with
  each authoritative effect; fixed-root operations use the equivalent control-journal record. At a
  terminal record's exact expiry the key may name a fresh effect. A terminal record restored from
  another runtime namespace causes a stable `command_namespace_changed` conflict until that expiry
  rather than authorizing or repeating an effect. Fixed-root records MUST carry a second
  backup-portable keyed reservation digest whose MAC generation is encrypted into artifacts; the local
  journal-integrity key remains host-only and is never reused for portable lookup. Lasting generation,
  key, rollback, or artifact dependencies live in generated-resource provenance, not in the expiring
  caller-key record, so terminal command reservation/result authority expires logically at the exact
  boundary even while the resulting resource or physically frozen rollback evidence remains retained.
  At or after that boundary the old record discloses no result, reserves no local/portable tuple, and
  creates no command-MAC dependency. Ordinarily its physical removal and any same-key fresh intent are
  one transaction/publication. During a rollback-eligible upgrade, the existing expiry timestamp makes
  that logical transition without a selected-state or journal mutation; frozen bytes remain inert only
  so either generation can be selected. Activation, rollback-clone selection, or final forward repair
  MUST prune every logically expired selected command row and remove it from the fixed journal's active
  reservation projection before releasing effects; immutable authenticated history may remain as
  non-authoritative audit bytes. Every command-expiry comparison uses the persisted validated safe-time
  authority from PR-149. A terminal boundary at or below its effective durable authenticated high-water
  is proven expired forever, including during a later clock hold; a null expiry and a boundary still
  above that high-water remain reserved while held. No caller key can become eligible for a fresh effect
  during the hold.
  The distinct fixed-root `addressed_state` class is used only by `clock.acknowledge` and
  `system.shutdown`; it carries no caller command key, seven-day result authority, portable reservation,
  or fresh-key namespace. Its request MUST address the exact current clock hold generation plus
  observation digest, or the exact current process instance, and MUST state the desired monotonic
  transition. The journal retains at most one current and one most-recently-completed cell for each of
  those two operations. Exact repetition against the newest current address, or its completed result
  before a newer address exists, returns the same safe phase/result without another effect; an older,
  future, or different address returns stable
  `state_address_conflict` and directs the caller to read current state. A newer clock hold or process
  instance may replace the prior completed cell only after its own address is durably current, so a
  delayed retry can never acknowledge a different anomaly or shut down a later process. Authentication
  and current authorization are rechecked before either mutation or result disclosure. This bounded
  addressed-state projection is independent of invocation count and remains journal-authoritative
  before SQLite exists.
  The distinct selected-state `generation_guarded` class is used only by `admission.set`,
  `principal.enable`, `principal.disable`, `grant.put`, and `grant.delete`. It carries no caller key,
  expiry window, or historical result ledger. Its complete revision address is the pair
  `(resource_incarnation, generation)`: `resource_incarnation` is the canonical lowercase 64-hex wire
  encoding of the selected state's authenticated structured 256-bit history epoch. Its first 192 bits
  are a purpose-separated owner-root namespace and its final 64 bits are that root's nonzero big-endian
  monotonic branch serial. It is a non-secret address, never an authentication or authorization
  capability. `generation` is a nonzero `u64`. Every
  request MUST carry both `expected_incarnation` and `expected_generation` for its
  admission resource, principal, or principal grant collection plus the complete desired transition.
  Authorized admission/principal/grant reads expose the current pair; the API and CLI never infer,
  fetch, or substitute either component.
  The selected state retains exactly one replace-in-place last-transition receipt for admission, one
  per principal for enable/disable, and one per principal grant collection for put/delete. A receipt
  binds the exact resource incarnation, prior and result generations, stable actor namespace, closed
  operation/desired-state/reason fields, and only a safe result reference; it contains no raw key,
  secret, general fingerprint, or MAC-key dependency.
  With the complete expected pair still current, an already-matching desired value is an effect-free
  no-op. Otherwise the desired state, checked incremented generation, authorization epoch where
  applicable, audit event, and replacement receipt MUST commit atomically. After response loss, an
  exact actor/closed-semantics/complete-address match against the still-current last receipt returns the
  current safe result without mutation. Every stale, future, branch-old, superseded, ABA, mismatched-
  body, or cross-actor request returns stable `state_generation_conflict` without effect and directs the
  caller to read current state.
  Every normal writer of one of these guarded resources MUST advance that resource generation or fail
  before changing either the resource or its command record. This includes `drain.start` even when
  operator admission is already closed, and `principal.update` even though those operations retain
  their command-key class. Fresh accepted drain start clears the admission receipt; same-key drain
  recovery is effect-free. Bootstrap creates the first incarnation. Restore and rollback branch
  selection allocate a new authenticated incarnation, reset every surviving guarded generation to one,
  and clear every guarded receipt after their typed quarantine/rollback state is final; ordinary
  restart, migration, activation, configuration/key transitions, and forward repair preserve the
  complete pair. The fixed-root journal owns the branch-serial high-water. Bootstrap, restore, and
  rollback are its complete allocator registry: the first durable transition intent advances and burns
  exactly one serial, binds the derived target plus source/parent truth, and same-intent recovery reuses
  those bytes. Aborted work never reclaims a serial, continuation allocates none, and an exhausted,
  mismatched, or detectably colliding target returns stable `state_incarnation_unavailable` before
  staging, selection, or pointer publication.
  Per-branch randomness is not a uniqueness dependency. No request, artifact, hidden default, or CLI
  option may choose the target namespace, serial, or incarnation.
  Same-root non-reuse is deterministic. Cross-host non-reuse relies explicitly on independent host-
  local journal keys and the 192-bit HMAC namespace's computational collision security; cloning or
  importing a fixed owner root/key into concurrently live hosts is unsupported, and a self-contained
  blank host cannot prove absence of an incarnation used only by an unrelated disconnected host.
  Exact same-command recovery resolves first, then a restore/upgrade hold that forbids the fresh
  transition, then nonmutating allocator validation. A transition permitted through its own hold still
  returns allocator unavailability before `clock_hold` when allocator state is its immediate blocker.
  With no pre-existing safety hold and usable allocator state, clock evaluation precedes fixed-root
  control-capacity admission plus any admission, drain, or coordinator conflict; capacity admission
  then precedes publishing or burning a new intent. If the branch serial is exhausted,
  v1 has no in-place retry or widening: the supported operator path is a new independently keyed blank
  owner root plus authenticated disaster restore, while the exhausted root remains unable to create a
  branch and all nonallocating recovery/status/delivery behavior remains available.
  Serial exhaustion alone does not block nonallocating delivery, authorized status, exact
  command/result recovery, or any continuation operation. Readiness reports the terminal allocator
  condition as `incarnation_exhausted` without claiming that those permitted operations are unavailable.
  The `incarnation_exhausted` condition is derived exclusively from the authenticated persisted
  `branch_serial_high_water` already at `u64::MAX`; a rejected allocating operation and a readiness read
  perform no readiness or allocator mutation.
  Generation arithmetic never wraps. A writer at `u64::MAX` returns stable
  `state_generation_exhausted` before any resource, receipt, epoch, audit, coordinator, or command-row
  change and degrades readiness with reason `generation_exhausted`; an effect-free read, exact receipt
  recovery, or same-value no-op remains available. That readiness state is derived from the resource
  value already persisted at `u64::MAX`; the rejected fresh writer performs no readiness mutation. Only
  a supported fresh branch incarnation or future widening migration clears that condition.
  Authentication and current authorization are rechecked before mutation or result disclosure.
  Receipt storage is bounded by current resources/collections, never invocation count.

## P-11. Security, privacy, and retention

- **PR-110.** Message bodies, titles, destination values, provider responses, idempotency/correlation
  identifiers, semantic fingerprints, API keys, and provider credentials are sensitive. They MUST NOT
  appear at any log level, in metric labels, process arguments, panic/core text, or default CLI
  listings. No debug mode or build profile may relax this rule.
- **PR-111.** Logs use generated identifiers and low-cardinality stable classes. Caller-controlled
  strings MUST NOT become metric labels.
- **PR-112.** Provider clients MUST disable redirects unconditionally, ignore ambient proxy settings
  unless an operator explicitly configures a proxy, and verify TLS certificates/hostnames against the
  configured trust roots with a documented minimum TLS version. There is no blanket insecure-TLS
  switch. Plain HTTP is allowed only for an explicit loopback IP-literal endpoint with no provider
  credential. DNS changes for an operator-configured HTTPS hostname are accepted within its hostname
  identity; commands cannot change the host, scheme, port, proxy, or trust policy.
- **PR-113.** Provider response bodies MUST be size-bounded, treated as untrusted, and redacted from
  diagnostics. Header count/bytes, compressed and decompressed bodies, read duration, and connection
  lifetime are independently bounded.
- **PR-114.** The state directory and backup MUST be owner-restricted. MsgRiver does not claim
  application-layer encryption at rest in the first slice; operators requiring it MUST use encrypted
  storage and protected backups.
- **PR-115.** Payload and destination are retained only while required for attempt or authorized dead
  letter replay. Default retention is: purge within one minute after provider acceptance; retain a
  failed/dead-letter payload for 24 hours; retain safe terminal metadata and idempotency evidence for
  seven days. Operators MAY set failed-payload retention to zero per connector, shorten other periods,
  or extend failed payload retention up to seven days with an explicit privacy warning. Evidence
  retention can never become shorter than its idempotency window. Independently, the minimal
  content-free restore-comparison ledger MUST remain continuous through every unexpired locally
  supported backup-provenance deadline; ordinary terminal/audit cleanup cannot shorten that evidence.
  Purge tombstones are distinct from seven-day terminal metadata and are retained indefinitely in the
  first slice; no operator-shortened ordinary retention can remove them.
  Continuity MUST be mechanically verifiable from a gapless batch sequence, exact event counts, and a
  digest chain anchored in the authenticated artifact/provenance—not inferred from a scalar floor. The
  chain MUST also bind an unforgeable history epoch and every typed epoch transition to the authenticated
  selected state, so a complete valid suffix from a sibling branch is not interchangeable. Purge events
  MUST contain the complete non-sensitive tombstone projection needed to derive, rather than trust, the
  post-snapshot tombstone set.
- **PR-116.** “Purged” means content and destination are no longer available through supported
  MsgRiver interfaces or active logical rows. The first slice does not claim forensic erasure from
  SQLite freelists/WAL, storage media, snapshots, or pre-purge backups. Existing backups remain
  sensitive until the operator's retention expires, and restoring one may resurrect payload.
- **PR-117.** An operator MUST be able to request immediate logical purge of a terminal message
  atomically with a durable `payload_purged_at` tombstone. A non-terminal target fails unchanged with
  stable `message_not_terminal`; the operator cancels and waits for terminal resolution before purge.
  Repeating purge for an already-purged terminal message is an idempotent no-op that returns the
  original safe purge result and tombstone identity without appending another purge event or changing
  its transaction watermark.
  Purged dead letters cannot be replayed and say so explicitly. A restore starts held and reapplies all
  tombstones present at the backup watermark before any provider traffic. With exact proven ancestry it
  derives and reapplies post-snapshot tombstones from the verified purge-event projection. The exact
  expected set is the authenticated artifact-image tombstone projection at its watermark union the
  derived verified suffix after the artifact head; current rows MUST equal that union by message,
  instant, reason, epoch, batch, and ordinal. Missing, extra, changed, or wrong-epoch rows fail comparison
  rather than becoming report input. Blank-state restore reports later tombstones unavailable and
  requires operator reconciliation, while unproved nonempty replacement is rejected.
- **PR-118.** Core dumps MUST be disabled for the service. Crash and error paths MUST preserve
  redaction guarantees.
- **PR-119.** The CLI MUST accept every sensitive request envelope through protected stdin, file, or
  file descriptor. It MUST NOT require or silently accept body, destination, idempotency/correlation
  identifier, provider credential, API secret, recovery secret, or imported key material in argv or
  environment variables. Protected files/descriptors named by a non-secret connection profile are
  allowed. Service-generated non-secret identifiers such as message, attempt, principal,
  provider, key, backup, restore, upgrade, and generation IDs MAY be argv values and structured log
  fields; they never confer authorization.

## P-12. Configuration and connector safety

- **PR-120.** Operational non-secret configuration is declarative, versioned service state and is
  validated in full before activation or readiness. Unknown keys and unsafe combinations MUST fail
  loudly. A minimal root-owned bootstrap envelope may name state paths, systemd credential roots, and
  pre-opened listeners, but MUST NOT contain provider registrations, policies, principals, grants,
  peer mappings, or other product configuration unavailable through API and CLI. Canonical complete
  configuration is capped at 49,152 UTF-8 bytes so its API envelope always remains below the ordinary
  65,536-byte command-body limit.
- **PR-121.** Provider secrets are injected from protected regular files or operating-system credential
  descriptors. A root-provisioned, bounded, atomic metadata catalog exposes only logical reference
  names plus a generation/digest to both normal and maintenance modes; it contains no value, path, or
  credential descriptor. Only normal mode receives the separately protected secret values.
  Maintenance validation therefore distinguishes an unknown name from a known name whose value is
  unavailable without gaining secret access. Catalog/value-descriptor provisioning MUST acquire the
  same fixed state-owner lock and replace the sealed generation only while both daemon modes are
  stopped; the platform adapter MUST also serialize provisioning against the next service start so the
  catalog and value descriptors come from one launch generation. Secret values in environment
  variables are rejected in the first release because the process cannot reliably erase or bound
  inherited environment exposure. SOPS is the deployment convention but not a runtime dependency of
  the portable binary.
- **PR-122.** Every connector is disabled until explicitly configured. Alias, driver, endpoint,
  timeout, concurrency, retry policy, and allowed destination constraints are operator-owned.
- **PR-123.** The first slice changes operational configuration only through API/CLI validation and
  maintenance-mode activation followed by a controlled restart; live reload is not supported.
  Validation examines the prospective complete configuration and outstanding work. Activation is an
  atomic generation change while the normal process is stopped. Invalid or incompatible replacement
  leaves the prior generation active; startup always revalidates the active generation and accepts no
  validation ticket as authority.
- **PR-124.** Every accepted message references the pinned non-secret connector identity snapshot from
  PR-044, and every attempt records the effective configuration and credential generations without
  persisting secrets. Credential rotation for the same provider identity may affect later attempts;
  endpoint/driver/destination-policy changes require a new connector identity.
- **PR-125.** Removing or renaming a connector stops new acceptance for that alias but MUST NOT reroute
  outstanding work. Missing credentials or implementation place referenced work in a visible
  non-terminal `held` state with `hold_reason = connector_unconfigured` and no provider attempts;
  expiry still applies. Changing driver type or endpoint identity under an alias with outstanding work
  fails validation unless the old pinned generation remains operable under a distinct retained
  identity.
- **PR-126.** Configured provider URLs MUST use an allowed scheme, contain no userinfo/query/fragment,
  have canonical bounded base paths, and pass the TLS/plain-loopback rule in PR-112. Connector URL
  joining MUST never interpret destination data as an absolute URL or path traversal.
- **PR-127.** Service-state and backup-recovery key generations MUST have list, generate/rotate,
  import where applicable, and safe retirement operations through maintenance API and CLI. One-time
  secret material is returned once through a protected response, is never recoverable from ordinary
  state, and MUST be escrowed by the operator. Retirement MUST reject a key still required by retained
  state or local backup evidence unless the operator supplies the operation's explicit destructive
  acknowledgement. A generated recovery key remains pending and unusable for new backups until the
  caller acknowledges the exact one-time-output digest through the same API/CLI operation; response
  loss can therefore strand only an unused, replaceable key. Generating and activating a successor is
  the recovery-ring rotation operation; there is no separate hidden `rotate` capability. At most one
  recovery generation is `active` and backup-selectable; backup is unavailable when there is none.
  Per-purpose MAC serial exhaustion is recoverable without data loss through a supported branch
  transition, which allocates a fresh key origin whose serial restarts at one, subject to the retained-
  ring capacity rule below; it requires no in-place re-keying and reuses no existing MAC key identity.
  Retained MAC-key ring capacity MUST instead be recovered by retiring a dependency-free generation or
  waiting for its covering dependency window; a branch transition MUST NOT be represented as freeing a
  retained-ring slot.
  Acknowledging or importing a successor
  atomically demotes its predecessor to retained/non-selectable while preserving it for artifacts that
  already name it. The official
  CLI auto-acknowledges only after exclusive protected-file creation, file and parent-directory fsync,
  reopen, and digest verification; stdout/pipe output remains pending until explicit acknowledgement.
  The generate request codec is a closed `generate`/`acknowledge` phase union keyed by the same command
  key. A retry after the one-time value is consumed returns only pending metadata and confirmation
  digest. A `pending_escrow` generation is never active, selected, or referenced by an artifact and is
  therefore dependency-free by invariant; after response loss it remains listable and may be retired
  and replaced using the ordinary explicit deletion confirmation, without a fabricated escrow or
  retained-artifact override acknowledgement. The pending phase record cannot age out: it remains
  addressable, without holding the transition gate, until the same-key exact-digest acknowledgement or
  a separately keyed retirement closes it. At most one `pending_escrow` successor exists; another
  generate request returns HTTP `409 recovery_key_pending_escrow` before intent or key creation until
  acknowledgement or retirement closes it.
  The acknowledgement's different phase body is the sole allowed same-key body transition; mismatched
  generation parameters, tag, or digest conflict. An acknowledgement with no matching generated
  command returns `command_conflict`, creates no journal/ring/file record, and does not reserve that
  command key, so a later matching generate request remains eligible.
- **PR-128.** An unavailable provider credential value for a previously valid connector identity MUST
  hold that connector and keep the daemon/status interface available. An invalid secret reference,
  identity mutation, or incompatible configuration candidate MUST fail validation rather than
  replacing the active generation. Each validation pass reads one atomic authoritative name-catalog
  generation. Maintenance activation repeats validation against its then-current generation and fails
  before pointer commit if reopening the fixed basename through the metadata-directory descriptor finds
  an inode/generation/digest change or a referenced name is absent; the host provisioner cannot replace
  the catalog concurrently because it must acquire the daemon-held owner lock. An earlier normal-mode
  report is never an authority ticket.
- **PR-129.** Bootstrap is a command-key-idempotent, secret-free generation activation. It creates the
  first stable operator and peer mapping but neither an API key nor an exported recovery key. A lost
  response is recoverable by retrying the same command key. Recovery-key generation and API-key issue
  use their dedicated paired operations after bootstrap; backup creation fails safely until an active
  recovery key has been generated and escrowed. Pre-bootstrap recovery-key import/generation is valid:
  bootstrap eligibility permits only the fixed owner lock, a valid fixed-root recovery ring/journal,
  the empty canonical `generations` directory (or only its own reclaimable staging entries), and its own
  reclaimable transition files in addition to an otherwise absent final state generation/pointer.

## P-13. Operator and client interfaces

### P-13.1. Versioned operation surface

`specs/operations.toml` is the normative first-slice operation catalog. It contains exactly one record
per capability, including method/path, allowed listener bindings, authorization, request/response
codec, idempotency class, risk class, and exactly one CLI command ID. The product surface includes:

| Capability family | Required operations |
|---|---|
| Provider discovery | Authorized provider list/detail and schema retrieval. |
| Message lifecycle | Submit, list, show, attempts, cancel, dead-letter list/replay, and payload purge. |
| Operation and evidence | Queue, connector health, audit, admission read/change, bounded drain, clock-hold read/acknowledge, health, readiness, metrics, and graceful shutdown. |
| Identity and authorization | Principal lifecycle, provider-grant lifecycle, API-key lifecycle, and peer-UID-mapping lifecycle. |
| Configuration | Export active complete non-secret configuration, validate a complete candidate, and atomically activate a validated generation in maintenance mode. |
| Cryptographic lifecycle | List/rotate/retire service-state keys and list/generate/import/retire separately escrowed recovery keys. |
| Backup and recovery | Backup create/list/show/manifest/download/cancel, bootstrap, restore upload/show/report/resume, and retained-state-generation list/delete. |
| Upgrade safety | Prepare/show, maintenance migration, held activation, and pre-activation rollback. |

Grouped prose above is explanatory only. A route, command, daemon handler, or documented service
function absent from the frozen catalog is unsupported and causes the parity gate to fail.

- **PR-130.** Errors use a versioned JSON envelope with stable machine code, safe human message,
  request identifier, and optional bounded retry hint. A clock anomaly rejects prohibited fresh work
  with HTTP `503 clock_hold` and a null retry hint because operator settlement has no truthful bounded
  delay. A selected-state mutator prohibited while pre-activation rollback remains eligible returns
  HTTP `409 upgrade_activation_pending`; that code takes precedence when both holds prohibit the same
  mutation. `upgrade_prepare_in_progress` has the same precedence over `clock_hold` throughout the
  nonterminal pre-watermark coordinator. After authentication/authorization, an `admission.set` whose
  complete expected incarnation/generation pair is current and complete desired value already matches,
  or whose exact request matches the still-current incarnation-bound last-transition receipt, returns
  the existing tuple as a read-equivalent no-op in every phase. Any other complete-address mismatch
  returns `state_generation_conflict` before hold disclosure. While the pre-watermark
  prepare coordinator is nonterminal, any different desired value returns HTTP
  `409 upgrade_prepare_in_progress`; a mutation that serialized before the coordinator is captured in
  its initial admission snapshot. After `prepare_failed` a different value proceeds against the restored
  terminal state; after a successful prepare watermark it remains prohibited by
  `upgrade_activation_pending` until activation, rollback, or forward repair ends that phase. The
  stable-code vocabulary is closed and also includes the MAC-key and idempotency-evidence codes
  (`mac_key_ring_full`, `mac_key_identity_conflict`, `mac_key_serial_exhausted`,
  `canonicalizer_unavailable`, `idempotency_evidence_corrupt`); these are per-operation response detail
  with fail-closed semantics, not operation-catalog identity, and add no operation to the surface.
- **PR-131.** Unknown request fields are rejected for command creation. Content type and API version
  are enforced. The `/v1` path is authoritative; a body `api_version` field is rejected as unknown.
- **PR-132.** Request body, header, response body, JSON structural depth, and processing deadlines are
  bounded. Every JSON codec accepts at most 64 nested arrays/objects; depth 65 returns the stable
  malformed-JSON `400` response before any store command, and no build may enable an unbounded parser
  feature. Slow or partial clients MUST NOT monopolize service capacity. A handler may return a definite pre-commit
  timeout only after atomically cancelling a still-queued mutation. Once the store actor marks a
  mutation `started`, the handler MUST await its bounded authoritative result or return a distinct
  `operation_outcome_unknown` response that makes no non-commit claim and requires same-key,
  addressed-state, generation-guarded, or monotonic idempotent recovery as cataloged. Receiver loss or
  a response deadline MUST NOT let an actor commit after a `408` response.
- **PR-133.** List operations require pagination and deterministic ordering and MUST exclude payload
  and destination by default. Cursors define stable progression despite concurrent inserts/deletes.
- **PR-134.** Fresh submit returns `201`; an equivalent idempotent replay returns `200`; mismatch returns
  `409`; validation returns `422`; admission saturation returns `429` with a bounded jittered retry
  hint; upgrade's rollback-eligible phase returns `409 upgrade_activation_pending`; clock hold returns
  `503 clock_hold` with no retry hint when upgrade is not already decisive; other unprovable durability
  returns `503`. Both successful forms include `message_id`, current state,
  `deduplicated`, `idempotency_expires_at`, and sticky effect-uncertainty fields.
- **PR-135.** Replay requires an operator-supplied replay-request idempotency key. One `(actor_principal,
  replay_request_key)` atomically maps to one new message. The child has a fresh `message_id`, retains
  the original owner for `status:own`, records the operator actor and `replay_of`, and uses current
  validated connector policy. The original owner—not the operator actor—MUST still have a current grant
  for that provider and the original owner MUST still be enabled; operator scope never substitutes for
  the child's provider authorization or re-enables a disabled principal.
  The child-insertion transaction MUST also recheck operator admission plus every clock, storage,
  restore, upgrade/quiescing, drain, and shutdown hold with the same precedence as any other fresh
  external effect. Operator control reserve permits the replay request to reach that transaction but
  never bypasses a closed admission or safety hold. Replay therefore cannot create actionable work
  after a drain or prepare has serialized its closing transaction.
  Different replay keys are deliberate additional external effects.
- **PR-136.** A dead letter is every `failed` command. `cancelled` and `expired` commands are not dead
  letters and cannot use the replay endpoint; a client or operator may submit a new command with a new
  idempotency key. Payload-purged dead letters remain listed but are not replayable.
- **PR-137.** Provider catalog list/detail uses deterministic ordering and the same uniform not-found
  rule as message ownership. Schema documents are bounded and canonical; catalog generation changes
  whenever any exposed capability, limit, support level, or authorization changes.
- **PR-138.** Every domain/client/operator capability exposed by MsgRiver MUST have both a versioned API
  operation and a CLI command with the same authorization, validation, result, and error semantics.
  CLI code MUST use the service protocol rather than opening live state. Starting the normal daemon or
  maintenance listener is the only service-lifecycle exception. Help, version display, shell completion,
  local JSON rendering, and choosing a client-side upload/download file are presentation functions,
  not service capabilities and MUST NOT inspect or mutate service state.
- **PR-139.** The checked-in operation catalog is independent source data frozen before implementation.
  Router construction, client dispatch, CLI parsing, authorization tests, documentation, and the parity
  manifest MUST each prove exact set equality against it. The implementation MUST NOT generate the
  expected set from its own route/CLI descriptors and then compare that set with itself. Compound
  `GET/POST/PATCH` rows are forbidden; each method/path/action is one distinct operation record.

### P-13.2. CLI surface

The CLI MUST provide:

- `msgriver serve` and `msgriver maintenance serve` solely to start listeners;
- one command for every operation ID in `specs/operations.toml`, including provider, message,
  dead-letter, payload, queue, connector, audit, admission, drain, clock, identity, grant, API-key,
  peer-mapping, configuration, state-key, recovery-key, backup, restore, state-generation, upgrade,
  health, readiness, and metrics families;
- `--json` machine-readable output with stable exit-code classes;
- `--request @-` / protected-file input for the entire sensitive command; secret-bearing argv forms are
  rejected.

Interactive convenience MUST NOT make the CLI depend on a TTY. Destructive or externally duplicating
operations require an explicit confirmation flag in non-interactive use. High-risk administration is
local-only but still uses the versioned API: bootstrap/restore target a maintenance-mode Unix listener,
and local administration targets the binding named by the operation catalog. Restore, configuration
activation, key-ring recovery, migration, and rollback require the normal daemon stopped. The CLI
resume command submits the complete report digest/watermark/six-acknowledgement API object and requires
matching explicit local confirmations for RPO, duplicate effects, resurrected payload, unresolved
tombstones, credential quarantine, and TCP policy; flags never replace or invent request fields. The CLI
never opens the live database, state directory, operational configuration, or key rings directly. A
dedicated client crate has no dependency path to the store crate. Adding a route, command, or service
function without its paired catalog entry and surface is a build failure.

## P-14. Observability and operations

- **PR-140.** Structured logs include timestamp, level, event code, generated request/message/attempt
  identifiers where applicable, connector alias, and safe outcome class. They exclude sensitive data.
- **PR-141.** Metrics cover admission, current states, attempt outcomes/latency, retry delay, dead-letter
  count, ambiguity/duplicate risk, queue age, connector health/cooldown, database health, and storage
  reserve using bounded labels.
- **PR-142.** The versioned `system.health` operation answers process liveness. The versioned
  `system.readiness` operation fails when the store cannot safely operate or admission safety is
  breached; a single provider outage degrades connector health but SHOULD NOT make the whole service
  unready for durable enqueue. Readiness exposes only a closed reason set, which includes MAC key serial
  exhaustion and an unavailable idempotency codec as recoverable or corruption-degraded conditions, and
  no reason exposes a resource, actor, serial, key identity, or generation value. There are no
  unversioned health, readiness, or metrics HTTP aliases.
- **PR-143.** Graceful shutdown stops admission and allows bounded in-flight completion. A lease whose
  external invocation may be in progress MUST NOT be released early; it completes under its fence or
  remains recoverable only after normal expiry with ambiguity recorded. Shutdown checkpoints state as
  appropriate and exits non-zero if safe shutdown fails. Normal and maintenance local listeners expose
  the same graceful-shutdown coordinator through paired API/CLI; a service-manager signal is an
  equivalent host lifecycle trigger, not a hidden state-mutation implementation. The accepted phase
  triggers independently of response delivery. `system.health` exposes the current opaque process-
  instance address to authenticated callers; API shutdown requires that exact address, and the CLI
  obtains and submits it. Exact addressed-state retries return the same phase while that process is
  current or most recently completed; a later process returns `state_address_conflict` and never
  replays an old shutdown into a boot loop.
- **PR-144.** Drain mode stops new submissions and finishes eligible queued work under a deadline. Its
  durable coordinator continues after request disconnect without occupying an API/store admission
  slot; a retry with the same command key reattaches to the same result. It MUST distinguish a
  completed drain from timeout with work remaining. `admission.show` exposes the current or most recent
  safe drain ID, original deadline, phase, and bounded terminal counts without exposing its command key.
  Both terminal outcomes leave operator admission durably closed; only explicit `admission.set open`
  reverses it.
- **PR-145.** Backup MUST use a SQLite-consistent mechanism and carry a signed/checksummed manifest
  containing schema version, binary compatibility, transaction-sequence watermark, included-time
  boundary, connector identity generations, and enough non-secret metadata to test restoration.
  Commands acknowledged after the watermark are outside that backup's RPO. Copying only the main
  database file while WAL is active is unsupported. The backup MUST terminate within a documented
  bound under the reference sustained-write workload. State-key material in the artifact MUST be
  authenticated and encrypted under a separately escrowed recovery-key generation that is not present
  in the artifact; theft of the artifact alone MUST NOT expose keyed low-entropy fingerprints. Each
  artifact and its local provenance record MUST state one exact `nonempty_restore_supported_until`
  deadline. Passing that deadline never weakens blank-state disaster restore, but nonempty replacement
  MUST fail before activation rather than claim an incomplete comparison. The authenticated manifest
  also anchors the canonical base tombstone count/digest/watermark, restore-comparison history epoch plus
  batch head, and the encrypted backup-portable fixed-command reservation MAC generations required by
  unexpired/null command records. The encrypted key section MUST close every reference in the image:
  API-key verifier peppers for all retained or suspended API-key rows; idempotency, replay, command-
  lookup, and semantic-fingerprint MAC generations for every live or retained row; deterministic retry-
  jitter generations required by the A-11.3 `JitterKeyDependency` predicate; artifact-authentication generations; and
  portable fixed-command reservation generations for every unexpired/null reservation. Missing,
  unknown, duplicated, unreferenced-by-image-or-framing, or wrong-purpose generations fail backup
  verification and restore.
  The backup-job creation transaction MUST also acquire a durable conservative running comparison pin
  at the then-current retained anchor before any online copy begins. Prefix cleanup treats that pin as
  an anchor barrier throughout copy and off-actor verification. It may become the exact completed-
  artifact provenance only in the durable completion transaction, or be released only in the terminal
  failed/cancelled transaction after owned artifact removal; no later claim that a pin existed closes an
  earlier compaction window.
  That same creation transaction MUST persist an immutable validated-safe-UTC execution deadline,
  every checked workload/component maximum and safety margin used to derive it, and same-boot monotonic
  mirror metadata. This execution bound is distinct from downloadable-artifact retention and nonempty-
  restore support. A restart conservatively reconstructs only the remaining portion of the original
  execution bound from those durable carriers and the authenticated safe-time high-water; it can never
  grant the job a fresh or extended runtime.
  Artifact availability MUST use one recoverable two-store publication protocol: a verified temporary
  artifact becomes durably owned by a SQLite job record before no-replace publication; the published
  file and its parent-directory barrier precede the single durable completion/provenance transaction.
  `complete`, manifest access, and download are impossible before that transaction. Startup MUST
  reconcile every staged/published prefix before backup status, download, cancellation, or retention
  cleanup becomes available. A crash at any file/SQLite boundary therefore converges to exactly one
  verified completed artifact or one explicit failed/cancelled job with no owned file and no leaked
  comparison-evidence pin; it can never expose an untracked artifact or a completed row whose file was
  not durably published. Artifact deletion likewise becomes authoritative only after unlink and the
  parent-directory barrier; completed backup provenance and its comparison-support deadline outlive
  removal of the downloadable copy.
  A clock anomaly beginning after backup admission freezes new copy, verification, framing, and
  publication progress under the job's original immutable deadline. Crash-safe reconciliation may
  remove owned invalid staging but cannot claim completion. Settlement either resumes that same job
  within the conservatively re-derived remainder or, after proving the original deadline elapsed,
  terminalizes loudly following artifact cleanup and comparison-pin release; it never extends the
  deadline, publishes under uncertain time, or leaves an endless coordinator.
  It excludes provider credentials, recovery-key bytes, and the host-local journal-integrity key.
- **PR-146.** Schema migration is transactional where possible, refuses incompatible downgrade, and
  requires a documented pre-upgrade backup/rollback path. After exact same-command recovery and
  resolution of any pre-existing restore/upgrade hold, and before creating a coordinator or hold,
  `upgrade.prepare` MUST authenticate the fixed-root header and atomically require
  `branch_serial_high_water < u64::MAX`. At MAX it returns `state_incarnation_unavailable` before
  coordinator, hold, admission, journal, or allocator mutation. At MAX−1 prepare may proceed; no
  allocating operation can interleave before phase exit, so a later rollback burns MAX exactly once
  and same-command recovery of that rollback remains available at MAX. With usable serial headroom and
  no pre-existing safety hold, PR-149's clock rule resolves before a nonterminal drain or control-
  capacity disclosure: a clock hold returns exact `503 clock_hold` with null retry hint; otherwise a
  drain that serialized first returns `409 drain_in_progress` with no prepare state or hold. Before
  creating its first coordinator or hold, under the transition gate and journal-publication lock,
  prepare MUST project and durably bind the complete worst-case fixed-root ordinary capacity from its
  own command record through phase exit. The reserved total is the prepare record plus the sum of the
  maximum encoded bytes and entries for exactly four protected roles—one complete-plan
  `upgrade.migrate`, one ordinary `upgrade.activate`, one `upgrade.rollback` that no other role may
  consume, and one `upgrade.activate` forward-repair command—plus the maximum shared divergence,
  resolution, and lasting-provenance projection. Each role maximum includes its complete command,
  reservation, intent, result, allocator, and role-local provenance. This conservative sum explicitly
  covers migrate → rollback serial burn → authenticated mismatch → durable divergence → forward repair;
  consuming the rollback role never removes the still-required repair role or shared projection.
  Insufficient bytes or entries
  return `control_capacity` before prepare intent, coordinator, hold, admission, journal, or selected-
  state mutation. The authenticated `upgrade_exit_capacity_binding` counts every unconsumed byte and
  entry as occupied against unrelated ordinary admission, survives restart and fold, and lets each
  protected command consume its role without repeating ordinary-capacity admission; exact same-command
  recovery consumes nothing further. A role cannot be reassigned or consumed by a different command
  key. Unused capacity is released only by the fixed-root publication that records prepare failure
  before a watermark or a completed activation, rollback, or forward repair after its selected-state
  mirror is durable. Every rollback validation capable of rejection precedes the serial burn. After a
  burn, an incomplete rollback remains nonterminal and same-command recoverable, or an authenticated
  mismatch consumes the bound divergence/forward-repair path; it never terminalizes while retaining
  rollback eligibility with neither path. The plan digest and binding include the exact fixed-root
  journal format, framing, MAC-key format, and per-role codec versions used to derive those maxima. A
  successor binary that cannot continue that exact format MUST fail before consuming any role; it may
  use an explicitly compatible writer or leave rollback/recovery authority intact, never reinterpret
  the reservation under a new encoding. It then MUST
  durably enter a connection-independent `quiescing` phase that closes admission, new dispatch, and new backup-create
  admission while allowing every invocation already dispatched under a valid fence to finish, time out
  into explicit ambiguity, and commit its outcome under PR-087's total precedence. Known acceptance
  commits normally. Any other outcome whose cancellation, expiry/max-age, or attempt-exhaustion guard
  is already decisive commits that terminal truth immediately; absent such a guard, permanent truth
  becomes `failed`, while every transient, rate-limited, authentication/configuration, or ambiguous
  outcome MUST enter `held` with `hold_reason = upgrade_quiescing`, its closed outcome class and bounded
  relative hint retained, and null message/circuit deadlines. Upgrade quiescence wins this label if the
  source is also unavailable; its sole hold-clear later invokes the persisted-key jitter derivation before
  ordinary projection and moves the row to `retry_jitter_unavailable` if that derivation remains unavailable.
  A later cancellation records
  `cancel_requested` without clearing that hold; autonomous expiry/max-age/attempt maintenance excludes
  it. Its sole release is the ordinary-outcome projection below. Deferred authentication/configuration
  truth is immediately visible in connector health as `quiescing_deferred`. Any backup publication
  or reconciliation coordinator already admitted at that first commit MUST reach exactly one durable
  `complete`, `failed`, or `cancelled` terminal state before preparation may continue; no half-published
  backup may be frozen into rollback eligibility. No prepare watermark, sealed rollback source, or
  rollback eligibility exists until one durable transaction proves zero external invocations, zero
  dispatching leases, no uncommitted outcome/cancellation truth, and no nonterminal backup coordinator.
  At the first hold commit, the coordinator persists one immutable validated-safe-UTC prepare deadline,
  its component maxima/margins, and a same-boot monotonic mirror. They derive from every remaining
  provider-invocation hard deadline, every remaining persisted dispatch-lease expiry, and any admitted
  backup job's remaining immutable durable execution deadline, plus the bounded fence-recovery,
  reconciliation, and outcome-
  commit margin. Restart reconstructs a conservative remaining wait from that same UTC deadline and the
  authenticated safe-time high-water; it may prove quiescence early but MUST NOT extend the deadline.
  Clock uncertainty keeps the stricter hold rather than inventing elapsed time. A worker crash MUST therefore leave enough time for its
  persisted lease to expire and for fenced ambiguity/outcome recovery to commit. A stricter clock,
  storage, restore, or integrity hold that prevents this proof wins. Inability to prove quiescence by
  the frozen deadline never offers snapshot rollback. The store actor serializes `admission.set`
  against the whole nonterminal coordinator. After authentication and authorization, an exact current
  complete-address/desired-state match or current incarnation-bound receipt is a read-equivalent no-op
  returning the existing durable tuple in every phase. A different desired value under the current
  complete address committed before the first transaction is the snapshotted prior intent;
  every different value afterward fails with `upgrade_prepare_in_progress` until either terminal
  transaction commits. Failure then permits ordinary admission mutation; successful
  prepare instead enters the stricter rollback-eligible freeze. Once the store is writable, one
  terminal FULL transaction records `upgrade_quiescence_unproven`, restores the exact pre-prepare
  operator-admission intent, clears only the upgrade-quiescing admission/dispatch/backup holds, and atomically projects
  every quiescing-held outcome under then-current safe time and ordinary cancellation, expiry, max-age,
  attempt, backoff, ambiguity, rate-limit, and shared-circuit rules. Authentication/configuration opens
  one connector-wide bounded probe circuit rather than one probe per message. If a clock anomaly blocks
  safe-time derivation, those rows instead become `clock_anomaly` with their deferred evidence and null
  deadlines retained. Every stricter hold plus every unresolved live lease/outcome remains untouched.
  Startup reconciles an interrupted failure before readiness; same-key retry returns that stable
  terminal failure, while a later preparation requires a
  fresh command key. No abort operation is hidden or required.
  Only the successful prepare transaction persists the exact admission/effect holds, source heads,
  named completed-backup identity, and prepare watermark. From that commit until either activation or
  rollback commits, the rollback-eligible state is read-only except for the cataloged upgrade
  transition itself, safe reads/probes and authenticated committed-result lookup, and fixed-root
  `clock.checkpoint`, `clock.acknowledge`, and `system.shutdown` lifecycle records that
  are authoritatively mirrored into whichever generation is selected. Every selected-state mutator and
  autonomous expiry, purge, cleanup, scheduler, lease, provider-outcome, admission/drain, identity,
  configuration, key, backup, restore, cancellation, or command-result transition is frozen; a request
  for one returns `upgrade_activation_pending`. A terminal command whose authenticated expiry boundary
  passes becomes logically inactive under PR-109 without command cleanup or a selected-state mutation.
  Before lookup first relies on that crossing, the allowed internal `clock.checkpoint` durably proves
  the nondecreasing high-water and mirrors only clock authority; it discloses no result and reserves no
  tuple, but its bytes remain inert rollback evidence until the selected hold-clear path prunes them. A
  later clock anomaly cannot revive that proven absence. An unexpected transaction/watermark change
  fails closed and permanently invalidates rollback rather than allowing it to erase state. Activation
  MUST verify the exact prepared source watermark, upgrade/target generation IDs, transition certificate, and
  complete allowed-mutation ledger before its activation transaction commits. Rollback MUST clone the
  recorded sealed source
  into a fresh generation, reconcile the allowed fixed-root lifecycle records, verify that target's
  exact certificate, and only then commit its pointer. Activation and rollback decisions use paired
  API/CLI operations rather than a hidden deployment-script mutation. An authenticated bounded
  fixed-root checkpoint plus tail MUST account for every state transition after the migration
  candidate is finalized. It carries a gapless ordered transcript commitment and the complete
  deterministic current projection, so raw records may compact without losing or inventing authority;
  only the closed three-record lifecycle registry above may enter that projection. Any clock settlement
  in this transcript—explicit acknowledgement or an event-triggered automatic-settlement checkpoint—may mirror
  only the fixed-root clock authority and a `deadline_derivation_pending` marker; it MUST NOT write
  message, circuit, scheduler, retry, lease, cleanup, or expiry deadlines.
  Activation, rollback-clone selection, or the final forward-repair hold-clear transaction MUST derive
  every `clock_anomaly` message/circuit deadline that is still null deterministically and conservatively
  from then-current validated safe time and retained relative evidence, apply the same ordinary-outcome
  projection to every `upgrade_quiescing` row, prune all logically expired selected command authority,
  clear the marker, and only then release effects. Every projection, hold clear, message/circuit
  deadline, terminal precedence result, and audit event commits together; no null-deadline row becomes
  scheduler-eligible. An unavailable or inconsistent required checkpoint/tail projection, an
  authenticated record or projected lifecycle kind outside that set, or an unexpected selected-state
  delta creates lasting fixed-root `upgrade_diverged` provenance that survives caller-command cleanup
  and blocks activation, rollback, and involved-generation deletion. A journal header/HMAC/sequence
  integrity failure is already persistent fixed-root corruption: the service MUST preserve it unchanged
  and fail closed rather than append, overwrite, or offer forward repair. The `upgrade.activate` API/CLI may resolve ordinary divergence poison only through
  its explicit `forward_repair` request variant, bound to the exact divergence digest and an explicit
  preserve-current-state acknowledgement, after all ordinary integrity/security/invariant checks pass;
  forward repair never revives snapshot rollback or silently accepts corrupt state.
- **PR-147.** The service MUST start with unavailable providers, retain accepted work, and retry under
  policy; provider startup order is not a service dependency.
- **PR-148.** Restore runs only through the local maintenance API with the normal delivery daemon
  offline, rejects a concurrently active state owner, invalidates old leases, and always starts the
  restored instance in `delivery_held`. Before resume it reports: snapshot
  watermark, commands absent after the RPO boundary, non-terminal/ambiguous work that may duplicate
  effects completed after the snapshot, and payloads that may have been resurrected. Restore MUST
  suspend all restored API keys, peer mappings, and provider grants; disable TCP; and create a fresh
  local recovery operator with an enabled UID-0 operator-ceiling mapping authorized by the maintenance
  peer. No restored remote credential
  can resume delivery. Provider traffic resumes only after that fresh local operator records explicit
  acknowledgement and deliberately re-establishes access. Restore to a second concurrently active
  instance is unsupported and blocked where detectable. Comparison against nonempty current state and
  tombstone replay are allowed only when an exact locally retained backup-provenance record proves that
  artifact's source instance, lineage, digest, and watermark are an ancestor of that current state. The
  first release rejects foreign or unproved nonempty-state replacement; blank-state disaster restore
  remains allowed with comparison unavailable. A proven nonempty restore additionally requires an
  unexpired artifact support deadline and continuous content-free comparison evidence from the
  artifact watermark through current state. Every contiguous comparison batch, declared event ordinal,
  event count, prior digest, and resulting digest MUST verify from the artifact-anchored head to the
  current head. Every batch binds its history epoch; every epoch boundary binds the exact parent
  epoch/head and is authorized by the active generation's host-authenticated control provenance. The
  selected head MUST terminate in that authenticated active epoch. Current purge tombstones MUST equal
  the authenticated artifact-image projection at its watermark union the post-head projection derived
  from verified suffix events; neither pre-snapshot rows nor post-snapshot rows are inferred from the
  other source. Missing, reordered, modified, sibling-transplanted, or compacted
  coverage rejects the restore before
  activation; the service MUST NOT emit a report that silently omits acknowledged post-watermark work.
  The held report is an immutable digest-addressed
  logical document: its summary and all generated-ID/detail entries are deterministically paginated
  under the single `restore.report` operation, every bounded page carries the same report digest, and
  a cursor is valid only for that digest. Live post-restore status counters are a separate overlay and
  never change the acknowledged safety report. Resume requires the exact immutable report digest and
  watermark, not one oversized response or a client-supplied summary.
  Every selected restore target MUST set durable operator admission to `closed` with a restore reason
  before pointer selection. Resume clears only restore safety holds; it MUST leave that operator state
  closed until a separate explicit `admission.set open`, regardless of artifact-era or descendant
  admission intent and including blank-host recovery. The fresh authenticated restore history epoch is
  also the new guarded-resource incarnation: after quarantine is final, admission and every surviving
  principal/grant collection start at generation one with null guarded receipts, so no request or
  receipt from the artifact, abandoned descendant, or sibling can address restored authority.
  On an independently keyed blank-root restore, authenticated artifact epochs remain only immutable
  foreign ancestry behind the typed restore boundary. They never become the selected target or a
  guarded-resource incarnation, never supply the new root's allocator high-water, and never authorize a
  request or receipt; the new root allocates its own namespace serial one as the sole selected target.
  The boundary count is relative to the current selected owner root: an artifact may carry earlier
  authenticated blank-restore boundaries inside its verified lineage, and all epochs behind the current
  root's immediate boundary remain foreign.
- **PR-149.** Absolute expiry uses validated UTC wall time; each authenticated last-safe wall-time marker
  is a durable nondecreasing high-water, and in-process lease and delay waits use a monotonic source,
  with persisted UTC deadlines reconstructed conservatively after restart. Where fixed-root and
  selected-state authorities coexist, the effective comparison high-water is the maximum of their
  authenticated markers, never their minimum or the uncommitted current wall time. A generation
  transition MUST carry forward the maximum present in all authenticated transition inputs before
  selection; it cannot claim preservation of a proof that none of those inputs contains. A forward
  or backward wall-clock step beyond the configured threshold pauses expiry/max-age transitions and
  new provider attempts, degrades readiness, and emits an operator signal until a settle window or
  explicit acknowledgement. On startup, both implausibly forward and backward offsets from persisted
  safe time enter the same observable hold rather than crash-looping or silently progressing time. The
  fixed root persists and authenticates its own last-safe wall-time high-water with every control-journal
  publication, through an autonomous internal `clock.checkpoint` journal record at a configured
  periodic interval in both runtime modes, at an automatic-settlement state change, and on clean
  shutdown. `clock.checkpoint` is an internal lifecycle record rather than a client operation and has
  no API or CLI surface; it advances safe time only from an observation accepted by the clock guard.
  Automatic settlement is not effective until its event-triggered checkpoint is durable and, when
  selected state exists, idempotently mirrored. Before any response relies on a newly crossed
  idempotency/command expiry above the effective durable high-water, the service MUST durably advance
  that authority with either the ordinary deletion/fresh-intent transaction or an allowed internal
  `clock.checkpoint` and required mirror. If that proof cannot commit, it returns a safe durability-
  unavailable result without redisclosing the old authority or admitting a fresh effect. The
  checkpoint interval defaults to and may not exceed one hour. The plausible-downtime ceiling defaults
  to seven days and MUST be strictly greater than the checkpoint interval plus the configured clock-step
  threshold and settle window;
  maintenance performs the same startup/runtime validation even before SQLite exists.
  While either mode is held, every time-based transition is fail-closed: message expiry/max-age, retry/
  provider effect, idempotency/command fresh-eligibility and cleanup, terminal `command_expires_at`,
  fixed-root journal cleanup, and drain/shutdown deadlines. Every new effect-bearing command or
  expiry-bearing submission is blocked with `503 clock_hold` and no retry hint, whether its key is
  retained, apparently expired, or never seen.
  No unresolved record is released against anomalous wall time. Authenticated status plus existing
  idempotency/command lookup and committed-result retrieval remain available for null-expiry or
  not-yet-proven-expired rows. A boundary at or below the effective authenticated durable high-water
  stays logically absent forever even if physical evidence remains: the hold cannot redisclose its
  result, conflict, namespace marker, or local/portable reservation. The same key is a fresh-effect attempt and
  therefore receives the stricter upgrade/restore hold or `503 clock_hold`, never the stale result.
  Error precedence under combined holds is total: an operation forbidden by an existing restore or
  upgrade hold returns that hold before clock evaluation; a transition explicitly permitted through
  its own hold returns `clock_hold` only when safe-time proof or deadline derivation is its immediate
  blocker and MUST leave the original hold set. With no such pre-existing safety hold, `clock_hold`
  blocks every fresh coordinator or effect before an admission, drain, or coordinator conflict can be
  disclosed.
  Exact-observation acknowledgement may settle only the clock authorities; graceful shutdown may record
  only lifecycle intent/result without advancing safe time; cancellation may make queued/held/retry work
  terminal or set `cancel_requested` on an in-flight attempt; and a provider invocation already started
  under a valid fence may finish and commit its fenced outcome evidence. None of these exceptions can
  cause cleanup, expiry, retry, lease release, or a new provider invocation in the same transaction, and
  a stricter upgrade/restore hold still wins. Known acceptance commits under PR-087's acceptance-first
  precedence; a permanent terminal outcome remains subject to cancellation/expiry precedence.
  Transient, rate-limited, authentication,
  configuration, or ambiguous evidence enters `clock_anomaly` hold with no circuit/retry deadline or new
  attempt until settlement derives one conservatively from safe time. Clock anomaly wins this label if the
  source is also unavailable; settlement invokes the persisted-key jitter derivation before ordinary
  projection and moves the row to `retry_jitter_unavailable` if that derivation remains unavailable. If automatic or acknowledged
  settlement occurs in normal mode, its fixed-root publication precedes one FULL selected-state mirror
  transaction that derives every anomaly-held null message and circuit deadline and clears the selected
  clock hold atomically. Until that mirror commits, the hold remains effective and no attempt may start;
  startup idempotently finishes or retains that fail-closed prefix. If settlement occurs during a
  rollback-eligible upgrade, its allowed lifecycle record and mirror set
  `deadline_derivation_pending` but defer every such deadline derivation until activation, rollback, or
  forward repair selects the final generation and is ready to clear that stricter hold. The derivation
  set is every message/circuit row held by the anomaly with a null scheduler-visible deadline, not only
  rows associated with an explicit acknowledgement.
  Cancellation committed during that invocation is resolved by PR-087 before any post-settlement
  attempt. A command that reached `expired` before the anomaly never becomes eligible again.
  All arithmetic on UTC millisecond instants used for expiry deadlines and their conservative post-restart
  reconstruction MUST use checked addition producing the exact sum without modular wrap. Checked UTC
  millisecond addition MUST detect i64 overflow and reject it with an `arithmetic_overflow` error rather
  than wrapping to an in-range instant. An expiry boundary at or below the effective authenticated durable
  high-water MUST be affirmatively classified as proven expired, and that classification MUST remain
  irrevocable even while physical evidence for the boundary still exists. The configured wall-clock step
  threshold MUST default to 30 seconds; an absolute forward or backward deviation beyond it, measured
  against a stable monotonic source, MUST enter the clock hold.
- **PR-150.** A fixed-root, keyed, crash-consistent control journal MUST make bootstrap, blank-state
  restore, generation transitions/deletion, recovery-ring changes, upgrade activation/forward repair,
  and API-triggered shutdown
  recoverable without assuming a selected SQLite database. Every stopped-state generation clone MUST
  be a WAL-complete logical SQLite copy with exact pre-mutation transaction-watermark equality; raw
  main-database copying is forbidden. Generation deletion shares the transition lock, and rollback
  activates a new clone of the sealed source rather than repointing to or mutating it. That rollback
  clone owns a newly allocated authenticated history epoch/resource incarnation, resets guarded generations to
  one, and clears guarded receipts only after its selected typed state is complete; continuation clones
  preserve the existing complete guarded addresses. Fixed-root
  command authority uses the host-only journal MAC, while a purpose-separated portable reservation MAC
  exists only to detect caller-key reuse after backup/restore; a portable match can block a repeated
  effect but can never authenticate journal contents or disclose a foreign result. The host-keyed active
  pointer/control provenance also binds the selected generation's history epoch. The journal is one
  HMAC-authenticated bounded state checkpoint plus a bounded ordered tail, not indefinitely retained
  raw history. Its checkpoint preserves every live/null command and local/portable reservation,
  still-required resource provenance, ring/pointer and safe-time/hold authority, exactly four bounded
  current/last `addressed_state` cells, and any open upgrade's deterministic lifecycle projection and
  transcript commitment. Periodic checkpoints and command
  expiry may fold the tail during rollback eligibility or `pending_escrow`; no long-lived phase pins
  physical history or makes publication work grow over time. A fixed-root operation that would exceed
  the ordinary `4 MiB - 16 KiB` checkpoint-byte/4,032-entry budget returns `503 control_capacity` before intent, staging,
  secret generation, or other effect. Ordinary admission cannot consume the separately reserved space
  consisting of a 2-MiB/64-entry checkpoint region for at most 60 reconciliation-projection entries plus
  the four addressed-state cells and an independent 2-MiB/128-record tail region,
  including terminalization of one worst-case admitted transition, clock/shutdown publication, or a
  capacity-reducing retirement. The only cross-operation ordinary-capacity reservation is the
  authenticated `upgrade_exit_capacity_binding` created by fixed-root-journaled `upgrade.prepare` before
  its selected coordinator or hold. It charges unconsumed bytes and entries against every unrelated
  ordinary admission and protects distinct migrate, ordinary-activation, nonfungible rollback, and
  forward-repair roles through the complete worst-case plan and divergence lifecycle. Each role converts
  its reservation into actual projection without another ordinary-capacity decision; exact recovery
  reuses it. Restart, fold, expiry, and caller-key loss cannot shrink or release it. Only terminal
  prepare failure before a watermark or a durable selected-state phase exit plus its matching fixed-root
  terminal publication releases unused capacity. A missing, under-sized, reassigned, or prematurely
  released binding while its phase remains open is fixed-root corruption.
  Resolved divergence poison/resolution pairs freeze a finite audit-
  support deadline of at most 365 days; checkpoint folding MUST omit a pair only after durable safe
  time proves that deadline expired and every named generation is absent. An unresolved or still-
  dependent pair is never removed. Interrupted operations
  reconcile both at startup and before any later fixed-root mutator: a prefix that can finish without new
  caller bytes finishes; a safely reversible prefix missing required input is rolled back and
  terminalized with a stable failure, releasing the transition gate so a different key can begin
  immediately. An input/body timeout or disconnect therefore cannot leave a null-expiry global wedge;
  same-key retry still receives the terminal result and no acknowledgement is guessed.

## P-15. Compatibility, packaging, and portability

- **PR-151.** Public API versions and CLI JSON output follow semantic compatibility rules. Additive
  fields MAY appear only where clients are required to ignore them; create-command unknown fields are
  rejected to prevent accidental intent. Destination/content discriminants and schema versions evolve
  independently inside that envelope; unsupported versions fail validation rather than being guessed.
- **PR-152.** Database schema compatibility and minimum supported binary for a data directory are
  recorded in release notes. Downgrade safety is never assumed.
- **PR-153.** The first distribution is one Linux binary plus sample config, systemd unit, license,
  and documentation. Runtime requires no language runtime, external broker, or database daemon.
- **PR-154.** Domain, queue semantics, and connector contracts MUST avoid systemd and Unix assumptions.
  Linux/systemd/Unix-socket integration lives at platform boundaries so future macOS, Unix, and
  Windows ports remain possible without claiming present support.
- **PR-155.** Releases are reproducible from a pinned Rust toolchain and lockfile and publish checksums
  and provenance appropriate to the release channel.

## P-16. Degradation policy

| Condition | Required behavior |
|---|---|
| Persistence cannot prove durability | Fail loud; reject new submission. |
| Authentication/authorization store unavailable | Fail closed for protected operations. |
| Connector unavailable | Continue durable admission within bounds; retry and report degraded connector. |
| Queue/storage safety limit reached | Fail loud for admission; preserve status and recovery access. |
| Metrics sink unavailable | Advisory degradation; delivery continues and warning is rate-limited. |
| Log sink unavailable | Follow operator-configured fail-loud startup policy; never bypass redaction. |
| Invalid configuration on startup | Fail loud before readiness. |
| Invalid configuration replacement | Keep prior valid snapshot; fail loud to operator. |
| Connector identity removed or credentials unavailable | Hold referenced work without attempts; keep expiry active and surface remediation. |
| Connector-wide rate/auth/config failure | Persist shared cooldown/circuit; bounded probes only; healthy connectors retain reserved capacity. |
| Time source jumps forward or backward beyond threshold | Pause time-based terminal transitions and new effects; degrade readiness until settled/acknowledged. |
| Upgrade is prepared but not activated or rolled back | Keep selected state read-only, return `upgrade_activation_pending` for prohibited mutations, and fail closed on any unexpected watermark change. |
| Payload was explicitly purged | Fail closed for replay; retain safe “payload purged” evidence. |
| State restored from backup | Start delivery held; report RPO, duplicate window, ambiguity, and payload resurrection before explicit resume. |
| Critical storage reserve breached after acceptance | Stop admission and pause effects whose outcomes cannot be durably recorded; preserve reserved control access. |

## P-17. Acceptance scenarios

The first-slice test plan MUST make every scenario deterministic except the separately marked live
proof.

- **AC-001 — Durable acceptance.** Force-terminate immediately after a successful submit under the
  production durability profile; restart; the same `message_id` and idempotency mapping remain queued
  or progress, never disappear.
- **AC-002 — Failed persistence.** Inject commit failure; submit returns a stable unavailable error and
  no acceptance identifier that implies success.
- **AC-003 — Equivalent idempotency.** Submit semantically identical JSON with different member order;
  both responses identify one command and one delivery, and the second is explicitly `deduplicated`.
- **AC-004 — Idempotency conflict.** Reuse a principal/key with changed content or destination; receive
  conflict and preserve the first command.
- **AC-005 — Principal isolation.** The same key from two principals creates independent commands;
  neither can infer the other's message through status; rotating a key preserves ownership and
  idempotency for its stable principal.
- **AC-006 — Transient retry.** Fake provider fails transiently twice and accepts once; delays and
  attempt evidence follow deterministic policy.
- **AC-007 — Rate limit.** Fake `429` with bounded, malformed, and hostile `Retry-After`; no early retry,
  no unbounded delay, and a shared connector cooldown prevents one probe per queued command.
- **AC-008 — Permanent failure.** Provider validation failure produces terminal `failed` after one
  attempt and a redacted dead letter.
- **AC-009 — Ambiguous attempt.** Provider observes the request then drops the response; MsgRiver
  records sticky ambiguity/duplicate possibility and retries under at-least-once semantics without
  claiming exactly once.
- **AC-010 — Lease recovery.** Terminate a worker with leased work; another worker cannot act before
  expiry and can safely recover after expiry using a newer fence; the stale worker cannot overwrite
  newer state when it later returns.
- **AC-011 — Cancellation race.** Cancel queued work prevents a new attempt; cancellation concurrent
  with an invocation exposes `cancel_requested` immediately and reports that provider effect may
  already have occurred.
- **AC-012 — Expiry.** No attempt begins at or after expiry, including after restart or retry delay.
- **AC-013 — Saturation.** Fill the configured queue/admission limit; new work is rejected retryably,
  accepted work, existing-idempotency results, and reserved authorized recovery remain intact.
- **AC-014 — Connector fairness.** A permanently failing or hung connector at its cap does not violate
  the configured healthy-connector wait bound.
- **AC-015 — SSRF boundary.** Commands containing URLs, encoded path escapes, hostile topic values,
  headers, or endpoint-like unknown fields cannot change ntfy destination host/path semantics.
- **AC-016 — Redirect boundary.** Fake provider redirects to another loopback listener; MsgRiver does
  not follow it and does not disclose content or credentials there.
- **AC-017 — Secret redaction.** Inject secret-looking content, destination, API key, and provider
  response, identifiers, and fingerprint candidates; captured logs/errors/metrics/core policy/process
  listing contain none of them at any log level.
- **AC-018 — Payload lifecycle.** Terminal success purges content/destination on schedule while safe
  status and keyed idempotency evidence remain; explicit logical purge of every terminal state makes
  replay fail closed and reports the documented forensic/backup limits. Purge against queued, held,
  delivering, or retry-scheduled work returns `message_not_terminal` with no mutation. Re-purge every
  already-purged terminal state and receive the original result/tombstone without a new event or
  transaction-watermark change.
- **AC-019 — Graceful shutdown.** Read the authenticated process-instance address, stop during enqueue
  and delivery, drop the API response after durable acceptance, invoke maintenance shutdown before
  bootstrap, retry the same address/desired transition, submit a stale or future address, start a later
  process, and crash before completion. The exact current address, or its completed result before a
  later process exists, converges to one coordinator and
  safe phase/result independently of the connection; every other address returns
  `state_address_conflict`, the fixed journal retains only its bounded current/last shutdown cells, and
  the terminal/startup result truthfully reflects the deadline without a boot loop. Repeat more than 64
  process instances and under clock hold: projection cardinality stays constant, lifecycle intent
  remains durable, a monotonic process grace may end only in safe exit/failure, and no persisted lease,
  expiry, cleanup, or provider effect advances.
- **AC-020 — Backup/restore.** Create backup under concurrent enqueue, verify its watermark, restore
  through the local maintenance API with delivery offline, pass integrity/migration checks, account
  for every command within the watermark, and prove provider traffic stays held until explicit resume
  with duplicate/RPO/payload warnings. Kill before and after temporary-artifact fsync, staged-job commit,
  no-replace publication, parent-directory fsync, and completion/provenance commit; startup must finish
  or remove exactly the journaled artifact, preserve/release comparison evidence correctly, and never
  expose an incomplete, missing, corrupt, or unowned file as a completed backup.
- **AC-021 — Configuration replacement.** Invalid config never replaces the current valid generation;
  a validated restart changes new acceptance while pinned outstanding work keeps its connector
  identity and every attempt records its generation without leaking secrets.
- **AC-022 — Local authorization.** Unauthorized filesystem user cannot connect; submitter cannot use
  operator actions; peer/key mapping creates the expected stable principal; authorized CLI can submit
  a complete command through stdin without argv disclosure.
- **AC-023 — API bounds.** Oversized, slow, malformed, duplicate-field, wrong-version, and unknown-field
  requests, including a body `api_version`, are bounded and rejected without durable side effects.
  For every JSON codec, exact nesting depth 64 succeeds when otherwise valid and depth 65 returns the
  stable malformed-JSON `400` before a store command. A reduced-stack debug run of the over-depth case
  neither panics nor overflows, and dependency-feature inspection rejects serde_json `unbounded_depth`.
- **AC-024 — ntfy conformance.** Loopback fake verifies exact method/path/header/body, encoding, timeout,
  UTF-8 fidelity, response bounds, classification, no proxy inheritance, and redirect policy.
- **AC-025 — Live ntfy proof.** Separately from automated tests, Sol submits a unique harmless smoke to
  the approved local ntfy endpoint, reaches `provider_accepted`, and records service/log evidence
  without content or destination leakage.
- **AC-026 — Capacity.** The documented reference run satisfies P-09.1 under the P-07.1 durability
  profile with no acknowledged loss.
- **AC-027 — No public-network tests.** The standard test gate succeeds with public egress denied.
- **AC-028 — Stable-storage barrier.** A storage fault model discards writes lacking a completed
  durability barrier; every returned acceptance and idempotency mapping survives, and a structural
  tripwire rejects a weakened production SQLite synchronous profile. The same model checks backup
  staged-row, final-name, parent-directory, completion/provenance, cancellation, and deletion prefixes;
  no stable prefix may claim `complete` without its verified final artifact.
- **AC-029 — Concurrent idempotency.** Many simultaneous equivalent/conflicting submissions, response
  loss, admission saturation, payload purge, and exact window boundary produce one deterministic
  winner, correct dedupe/conflicts, and a new delivery only at/after expiry. After removing submit scope
  or the provider grant, a still-valid credential for the exact enabled owner recovers the existing
  result but a miss cannot create work; revoke the credential or disable the principal and both existing
  and missing-key requests fail before result disclosure.
- **AC-030 — Terminal idempotency honesty.** Re-submit after `failed`, `cancelled`, `expired`, and
  `provider_accepted`; each returns the old state with `deduplicated = true`, never a fresh-success
  implication. A deliberate new key creates new work; per-channel key guidance avoids collisions.
- **AC-031 — Effect-uncertainty matrix.** Combine ambiguous effects with retry exhaustion,
  cancellation, expiry, later known acceptance, and a successful duplicate; uncertainty stays sticky
  and known acceptance follows the precedence contract. Commit cancellation before expiry and expiry
  before cancellation around the same fenced non-accepted outcome; if both guards are present at
  projection, cancellation wins. A row already terminalized by an earlier transaction stays an
  idempotent terminal no-op for every non-acceptance outcome or failed guard. The one exception is
  matching verifiable acceptance: it promotes `failed`, `cancelled`, or `expired` to absorbing
  `provider_accepted`, retaining every newer attempt/guard/uncertainty fact and starting no attempt.
  Repeat at outcome commit, after restart, and after entry into `upgrade_quiescing`, including accepted,
  permanent, and ambiguous outcomes. Exercise the promotion before and after restart for each of the
  three terminal source states and through the upgrade-held projection; unmatched or unverifiable
  acknowledgements remain terminal no-ops.
- **AC-032 — Zombie writer.** Stall worker A beyond lease expiry, let B recover/finish, then complete A
  with accepted, transient, and ambiguous variants; no stale rollback occurs and all safe evidence is
  monotonic. Connector timeout plus the minimum commit margin is rejected at exact lease equality and
  every smaller value; only a strictly greater lease passes configuration validation.
- **AC-033 — Connector identity pinning.** Queue work, rotate credentials, remove/rename an alias, and
  attempt endpoint/driver/policy mutation; only allowed rotation proceeds, no work silently reroutes,
  and incompatible configuration fails or holds work exactly as contracted.
- **AC-034 — Replay idempotency.** Drop a replay response after commit and race repeated requests with
  one replay key; exactly one child/effect exists. A distinct key deliberately creates another child;
  owner, actor, causal link, purge race, current connector policy, and the original owner's current
  provider grant remain correct. Revoking that grant makes a fresh replay fail closed despite the
  operator actor's scope. Disabling the original owner also makes replay fail closed and never lets an
  operator reactivate that principal's egress. Race replay against admission close, both drain terminal
  outcomes (`complete` and `timed_out` with remainder), and prepare's first quiescing transaction in
  both actor orders; no child can serialize behind the already-closed admission or closing proof, and
  control reserve never bypasses the resulting admission/safety hold.
  Independently race a fresh same-key submit against `drain.start`, `complete`, and `timed_out` in both
  actor orders: it is exactly one durable accept-before-close or retryable reject-after-close, response-
  loss retry recovers the accepted result without another effect, and neither terminal reopens admission.
- **AC-035 — Authorization matrix.** Test every P-10.3 operation with peer-mapped submitter/operator,
  own/other principal, guessed ID, loopback bypass, rotated/revoked key, invalid-auth flood, and first
  bootstrap; denials fail closed without existence or secret leakage. Fill every bounded slow-header/
  preclassification slot and cross its byte/time boundary: excess traffic fails uniformly and releases
  capacity, no partial header enters a verifier queue, and this explicitly excluded distributed-DoS
  workload carries no valid-principal latency claim. Exhaust one source bucket and the global unknown-
  ID abuse budget, then, from the instant a complete syntactically valid known-key header is classified
  against the published index, prove the request uses the reserved lane and completes authentication
  within 250 ms in the deterministic reference test. Separately flood one known public ID from many
  sources and prove it leases at most one verifier globally while a classified valid different ID
  receives a fair permit and completes within the same bound. Saturate the bounded distinct-ID queue
  and verify excess work receives the documented retryable failure without weakening dummy work,
  constant-time comparison, or authorization; no latency promise is asserted for that many-ID attack.
  Race principal enable/disable and API-key issue/rotate/revoke at every durable-commit/index-
  publication/response boundary: no response is observable before the exact epoch is published, and an older index
  snapshot never authorizes through the durable-row/epoch recheck. For both principal transitions and
  both provider-grant transitions, exercise an initial effect and no-op through API and CLI; drop the
  response after commit/publication, recover exactly while its generation remains current, then commit
  the opposite transition by the same and a different operator before retry. Exact current receipt
  recovery has no second effect; stale, future, ABA, mismatched-body, cross-actor, and superseded
  generation cases return `state_generation_conflict`, never revive a principal credential/grant,
  never regress the authorization epoch, and remain identical after restart. Concurrently disable/descope the
  sole operator principal and update/delete/remap its sole UID-0 peer mapping: every serialized
  prospective state retains one enabled UID-0 operator path or returns `last_local_operator`, including
  response loss/restart. Adding a replacement first permits later predecessor removal.
- **AC-036 — Principal and connector isolation.** One principal and one failed connector exhaust their
  configured shares; another principal/healthy connector and operator reserve continue within the
  declared bounds.
- **AC-037 — Storage reserve.** Fill queue and filesystem while growing WAL and running backup; admission
  closes before emergency space is lost, readiness degrades, unsafe effects pause, and status/recovery
  stay available.
- **AC-038 — Clock anomaly.** Move injected time forward/backward across lease, retry, message expiry,
  max-age, idempotency expiry, terminal command expiry, fixed-root cleanup, drain, and restart boundaries
  in both normal and pre-state maintenance modes. Every time-driven transition and every new effect-
  bearing or expiry-bearing admission pauses during anomaly; existing deduplication/command-result lookup
  remains available only for null-expiry or not-yet-proven-expired retained rows, while proven-expired
  authority stays absent. Fresh, apparently expired, never-seen, and expiry-bearing admissions return
  the same `503 clock_hold` with null retry hint in both modes. Complete
  an already-started provider invocation with accepted, permanent, transient, rate-limited,
  authentication, configuration, and ambiguous outcomes during the step; fenced evidence commits, but
  only known acceptance/permanent truth becomes terminal. Every other outcome enters `clock_anomaly`
  with null retry/circuit deadlines, starts no retry/effect, and belongs to both explicit and automatic
  settlement derivation sets. Cancel queued/held/retry/delivering work
  during the hold and prove terminal/`cancel_requested` precedence without lease release or provider
  invocation. Exercise checkpoint interval/ceiling validation and the exact one-hour/seven-day defaults.
  No record releases early or expired command revives. Exercise both explicit acknowledgement and the
  automatic settle window; crash the event-triggered checkpoint before/after its fixed-root publication
  and SQLite mirror, and prove deterministic resume from persisted safe time. First prove expiry for
  domain idempotency, generic command, foreign-namespace conflict, and local/portable fixed-root
  reservation, then enter a later backward/forward anomaly and crash every high-water publication/
  mirror prefix: old authority never reappears, unresolved comparisons stay held, and no fresh effect
  starts. With no restore/upgrade hold, invoke `backup.create`, `upgrade.prepare`, and `drain.start`;
  each returns exact `503 clock_hold` with a null retry hint before coordinator creation or lower-
  priority conflict disclosure. Start a drain first, keep it nonterminal with a known positive
  monotonic remainder, then enter a clock hold and invoke a fresh `upgrade.prepare` with usable branch-
  serial headroom in both actor orders; it returns the same `clock_hold` before `drain_in_progress`,
  control-capacity, or coordinator disclosure and changes no prepare, drain, allocator, or reservation
  state. After authentication/authorization, invoke `admission.set` with the
  already-current complete desired value and with a different value under a pure clock hold: the exact
  match returns the existing tuple as a read-equivalent no-op, while the different value returns exact
  `503 clock_hold` and commits nothing. Admit a backup before the anomaly at every copy, verification,
  staged-publication, and restart prefix. The hold starts no new copy/publication step and cannot claim
  completion; only crash-safe reconciliation/owned-artifact cleanup may advance. Settlement resumes the
  same job only within its original conservative deadline, otherwise it terminalizes loudly after
  proven expiry with no published artifact or leaked comparison pin. Before the anomaly, durably commit
  cancellation intent at each prefix and prove its no-effect owned-artifact cleanup plus terminal
  transaction may finish under retained deadline proof. At the same prefixes, issue a new
  `backup.cancel` only after the clock hold exists: it returns exact `503 clock_hold` with a null retry
  hint, changes no job, file, pin, or deadline state, and cannot be reinterpreted as cleanup authority.
  Under combined holds, every operation forbidden by the pre-existing
  hold returns that hold first. Invoke each cataloged transition permitted through its restore/upgrade
  hold while clock proof is unavailable and verify an immediate-blocker `clock_hold` leaves the pre-
  existing hold intact; when clock proof is not the immediate blocker, the original hold remains the
  result. Start a drain, inject a clock anomaly while its deadline still has a known positive monotonic
  remainder, and race a fresh same-key submit against the paused drain deadline in both actor orders.
  The submit returns `503 clock_hold` with a null retry hint before admission/drain disclosure, the
  exact remaining drain budget stays frozen, settlement resumes that same remainder rather than a new
  deadline, and restart never opens admission. For normal-mode acknowledgement and automatic
  settlement, crash after fixed-root unique-temporary write, temporary-file fsync, atomic replacement rename, and
  parent-directory fsync, then before, during, and after the selected-state FULL mirror transaction.
  Run every prefix for both settlement causes. All anomaly-held null message/circuit deadlines are
  derived in that transaction with the hold clear, or the hold remains and no attempt starts; startup
  finishes the one authenticated published observation idempotently rather than creating another.
- **AC-039 — Restore duplicate window.** Back up, retain its exact local provenance, complete effects,
  purge payloads, age ordinary terminal/audit rows out, then restore that older snapshot before its
  exact support deadline; delivery stays held, the content-free comparison ledger keeps the RPO/
  possible re-delivery/payload-resurrection report complete, only proven-descendant tombstones reapply,
  and explicit resume is audited. Include purges both before and after the snapshot and compact comparison
  events older than the artifact head: the authenticated artifact projection plus derived suffix equals
  current indefinite tombstones exactly. After the deadline or any injected coverage gap, nonempty
  restore fails before activation instead of producing a partial report.
  Close operator admission after the artifact watermark, then restore both that proven ancestor and a
  blank host: selection durably records restore-closed admission, resume never changes it, and only a
  later independent `admission.set open` admits a fresh submit.
- **AC-040 — Fingerprint privacy.** After payload purge, identical/different idempotency checks still
  work, while a one-million-candidate low-entropy payload set cannot be tested against persisted
  evidence without the service MAC key; MAC-key rotation retains required old-key coverage.
- **AC-041 — Provider endpoint hardening.** Reject userinfo/query/fragment, unsafe schemes, invalid
  loopback plaintext, inherited proxy, untrusted TLS, oversized headers/compressed bodies, redirect,
  and hostile ntfy topics; no secret reaches an unintended listener.
- **AC-042 — CLI disclosure.** Submit every sensitive field through supported stdin/file descriptors;
  inspect argv, environment policy, shell-visible output, errors, and process listing; no prohibited
  value appears and sensitive argv forms fail.
- **AC-043 — Drain truthfulness.** Drain an accepting connector and a never-finishing connector, drop
  the initiating connection after commit, retry the same command key, and restart during the wait;
  completed and timed-out-with-remainder results, exit codes, durable closed admission, connection-
  independent progress, and lease handling are distinct and correct. `admission.show` exposes the safe
  current/latest result even when the original command key is unavailable. While a drain is running,
  inject a clock anomaly with a positive remaining monotonic deadline budget and race a fresh same-key
  submit against that paused deadline in both serialization orders. It returns exact `503 clock_hold`
  with a null retry hint before admission/drain disclosure; the deadline stays frozen, settlement
  resumes the exact remainder, and admission remains closed across response loss and restart.
  At start and at each terminal transaction, race a fresh submit in both serialization orders and lose
  its response: the command is durably accepted before closure or retryably rejected after it, never
  silently lost, and admission remains closed in every terminal/restart prefix.
- **AC-044 — Durable cooldown and retry.** Restart during `retry_scheduled` and connector cooldown;
  neither delay resets to zero nor work disappears, and recovery ramps within configured bounds.
- **AC-045 — Schema evolution.** Closed destination/content schemas accept supported discriminants and
  byte-faithful UTF-8, reject free-form provider JSON/unknown versions, and keep destination addressing
  separate from content/template data.
- **AC-046 — Single state owner.** A second daemon or restored copy cannot operate the same state
  concurrently; stale lock recovery does not violate leases or durability.
- **AC-047 — Provider discovery.** Two principals with different provider grants receive deterministic,
  generation-tagged catalogs containing exactly their allowed schemas/limits; disabled/unauthorized
  providers are uniformly absent, and endpoints, templates, headers, credential references, and other
  operator-only fields never appear.
- **AC-048 — API/CLI parity.** A generated operation matrix invokes every supported capability once
  through its API contract and once through the CLI, asserting identical authorization, state effect,
  result/error code, and redaction. Only normal/maintenance listener startup lacks an API equivalent;
  no CLI command opens live SQLite, operational configuration, state directories, or key rings. The
  expected operation set comes from frozen `specs/operations.toml`, not implementation descriptors.
- **AC-049 — Saturated idempotency pre-pass.** Exhaust new-admission and ordinary API/store mailboxes,
  then lose an equivalent submit response; the retry returns the committed command through reserved
  capacity. A miss proceeds to admission, which atomically rechecks before creating work.
- **AC-050 — Canonical idempotency across rotation.** Submit equivalent commands before and after
  credential and same-identity connector-generation rotation, with omitted defaults and permuted tag
  order; they deduplicate. Any changed client-semantic field conflicts. Private connector identity is
  not part of the client fingerprint.
- **AC-051 — Effective authorization and revocation.** Exhaustively test UDS peer-only, matching bearer,
  mismatched bearer, invalid bearer without fallback, TCP bearer, scope intersections, and durable
  revoke races; no wider credential widens a narrower principal/peer ceiling. Pin the post-revocation
  domain-key matrix separately from command-key results: a valid exact owner may recover an existing
  submit result after submit-scope/provider-grant removal, while a disabled principal, revoked key,
  different owner, command-key operation, or fresh effect remains denied without existence leakage.
- **AC-052 — Configuration ownership.** Export, validate, and activate a complete operational
  configuration through both API and CLI. Invalid/incompatible candidates keep the prior generation;
  direct file replacement cannot alter providers, policies, mappings, or grants. Every accepted
  canonical configuration fits below 49,152 bytes and every request envelope fits below 65,536 bytes.
  Maintenance validates names against the root-provisioned metadata-only secret-reference catalog
  without reading values; unknown names fail before pointer commit, an attempted concurrent provisioner
  cannot acquire the shared owner lock, platform start/provision jobs cannot overlap, and injected
  current-basename inode/generation/digest mismatch fails closed. A known name with an unavailable
  value activates only into the contracted connector hold.
- **AC-053 — Sustained-write backup.** Maintain the reference enqueue rate while online backup advances
  in bounded actor-owned page steps; it completes within the declared bound, has a verified watermark,
  and does not starve durable admission or reserved control work. Populate every service-key row class,
  including suspended API keys and unexpired/null portable reservations; missing, extra, duplicated,
  wrong-purpose, or wrong-generation encrypted key entries fail artifact self-verification and restore.
  Race cancellation, restart, retention, and status/download at every publication boundary: a staged
  verified temp resumes publication, a verified final resumes completion, partial/corrupt/missing
  artifacts fail loudly, reserved-name orphans are removed without following links, and a running
  comparison pin becomes completed provenance or is released only after durable artifact removal.
  Attempt comparison-prefix compaction from job creation through copy completion and off-actor
  verification: the creation-transaction pin prevents the anchor crossing until the completion or
  removal transaction atomically converts/releases it. Introspect the migrated schema and every
  creation/crash prefix: the validated-safe-UTC execution deadline, each derivation component/margin,
  and same-boot monotonic mirror are non-null durable job-row carriers distinct from retention/support;
  restart reconstructs a conservative remainder from exactly those bytes and never extends it.
- **AC-054 — Restore credential quarantine.** Restore an artifact containing formerly valid keys,
  mappings, and grants. Every restored credential is unusable, TCP is disabled, and only a fresh
  maintenance-peer recovery operator can inspect the report and deliberately rebuild access/resume.
  Raw API and executable CLI must submit the same digest, watermark, and six acknowledgement fields,
  one of which is the TCP-policy choice; omitting or mismatching any local confirmation fails before
  the resume request.
- **AC-055 — Recovery-key lifecycle.** Generate/export-once, import, generate a successor, and retire
  recovery-key generations through API and CLI. Missing required escrow fails restore with its safe
  generation ID; retirement while retained evidence depends on it fails unless the exact destructive
  acknowledgement contract permits it. Fault every official-CLI protected-file write/fsync/parent-
  fsync/reopen/digest/acknowledgement prefix; no backup may select a key before durable verified escrow.
  The closed generate/acknowledge phase union reuses one command key. Losing the response after durable
  one-time consumption returns only pending metadata on retry; that dependency-free pending generation
  remains listable and can be explicitly retired/replaced without claiming escrow occurred.
  Same-key generate retry with changed parameters and acknowledge with any wrong tag/digest conflict;
  the exact acknowledgement phase remains possible after arbitrary time/restart until retirement.
  Acknowledge before any matching generate returns `command_conflict`, creates no journal/ring/file
  authority or command-key reservation, and a subsequent generate with that key can succeed. Attempt a
  second pending successor before resolving the first and prove it creates no key or intent.
  Successor acknowledgement/import leaves exactly one backup-selectable generation and atomically
  demotes the predecessor without breaking artifacts that already name it.
- **AC-056 — Crash-consistent generation activation.** Kill at every create/fsync/pointer-rename/fsync
  step of restore, configuration activation, service-state-key rotation/retirement, migration, and
  rollback, with acknowledged source rows present only in WAL. Race deletion against every transition.
  Source/staged pre-mutation watermarks match exactly; startup selects one complete committed generation
  or fails closed and never observes a missing/partially mixed state. State-key retirement,
  recovery-key retirement, and state-generation deletion each carry a command key; kill after journal
  intent and after `.deleting.<command_digest>` rename, then retry the same/different key and prove
  deterministic completion/conflict with no orphan tombstone. Restore and rollback crash prefixes
  select either the old branch with every old complete guarded address intact or the new branch with
  one intent-bound newly allocated incarnation, generation-one guarded resources, and null receipts; no prefix
  exposes a mixed incarnation/generation pair.
- **AC-057 — Upgrade rollback watermark.** Prepare and migrate held state, exercise pre-activation
  rollback, then activate and accept/effect post-watermark work. Fill the ordinary fixed-root projection
  to the exact byte and entry boundaries around the canonical complete-exit calculation. One byte or
  entry short makes prepare return `control_capacity` before fixed-root intent, coordinator, hold, or
  selected-state mutation; the exact-fit control durably binds prepare plus all four protected roles.
  Attempt unrelated ordinary admission after binding and prove it counts every unconsumed reservation
  as occupied. Then consume migrate and ordinary activation, migrate and rollback, and divergence plus
  forward repair in separate runs; additionally execute migrate → rollback serial burn → authenticated
  mismatch → durable divergence → forward repair and prove the exact-fit sum retains the consumed
  rollback projection, the repair role, and the maximum shared divergence/resolution/provenance bytes
  simultaneously. Each role bypasses a second ordinary-capacity decision, no role steals the dedicated
  rollback reservation, and unused capacity releases only with the matching durable phase terminal.
  Crash and restart before and after prepare-intent publication, selected coordinator,
  every role conversion, checkpoint fold, selected phase exit, terminal mirror, and binding release;
  every prefix selects either no coordinator and no binding, or one open coordinator with its complete
  binding, or one complete terminal with no stale reservation. Make every rollback validation fail in
  turn before serial burn. After burn, inject filesystem/durability interruption and authenticated
  mismatch separately; exact same-command recovery completes the former, while the latter consumes the
  bound divergence/forward-repair path, and neither leaves a terminal rollback with no safe exit. Bind
  the plan to the exact fixed-root journal format, framing, MAC-key format, and per-role codecs; start a
  successor binary with each incompatible version in turn and prove it fails before role consumption
  while compatible continuation or rollback authority remains intact.
  Race `drain.start` against prepare in both actor orders without a clock hold: a running drain makes
  prepare return `drain_in_progress` before any hold, while a committed quiescing phase prevents a later
  drain or replay from starting. Repeat with the drain nonterminal under a pure clock hold and usable
  serial headroom: fresh prepare returns `clock_hold` before drain or capacity disclosure and changes
  neither state. Race replay against the
  same first transaction and prove it either commits wholly before the closure or returns the fresh-
  effect hold without a child. Race `admission.set closed` against the first prepare transaction and
  against both `prepare_failed` and successful-watermark terminal transactions in both actor orders,
  with response loss and restart at each FULL commit. In both first-transaction actor orders,
  read admission address `(I, G)`, send `admission.set closed` with `expected_incarnation = I` and
  `expected_generation = G`, drop its response, and restart after its durable `(I, G+1)` admission-row/
  incarnation-bound-receipt commit but before its caller
  observes serialization against prepare. The snapshot captures exactly that committed intent,
  `admission.show` returns its tuple, and an exact same-actor/closed-semantics/complete-address retry
  matches the still-current receipt and returns the same tuple as a no-op even while prepare is
  nonterminal. Commit a later opposite admission transition and prove the old request now returns
  `state_generation_conflict` without reopening or another audit event. Add a clock hold in that phase:
  exact receipt recovery or a current-address same-value no-op still returns the tuple, while a
  current-address different value returns
  `upgrade_prepare_in_progress` before clock evaluation. Lose a post-quiescence conflict
  response separately: repetition during that phase returns the conflict; after a terminal it may be
  evaluated only if its complete expected address remains current because no successful transition receipt
  exists. A pre-coordinator change is captured exactly; a different desired value during the nonterminal
  window returns `upgrade_prepare_in_progress`; a post-terminal change
  after failure applies to restored terminal truth, while one after the successful watermark returns
  `upgrade_activation_pending`; neither terminal path may regress the admission tuple. At prepare, hold
  new dispatch while
  racing accepted, permanent, transient, rate-limited, authentication, configuration, ambiguous,
  timed-out, and cancellation-precedence outcomes from already-dispatched invocations. Assert accepted
  truth wins; otherwise cancellation, expiry/max-age, and exhaustion already decisive at outcome commit
  terminalize in that exact order. For every remaining nonterminal outcome, assert
  `upgrade_quiescing`, retained closed outcome/relative evidence, null message/circuit deadlines, and
  deferred auth/config connector health. Commit cancel and cross expiry/max-age after that hold; the
  row stays held, records the guard, and every generic maintenance path ignores it. Release those rows
  after (a) `prepare_failed`, (b) watermark plus
  activation, (c) rollback clone, and (d) final forward repair. Crash before/during/after each outcome,
  terminal, and hold-clear FULL transaction; require exactly one normal-outcome projection, conservative
  message/shared-circuit deadlines, sticky ambiguity, exact terminal precedence, one audit event, and no
  null-deadline eligibility. The auth/config projection creates exactly one connector-wide circuit
  record and shared probe deadline. Repeat with an active clock anomaly: conversion to `clock_anomaly` retains
  null deadlines until settlement applies that same projection. After retaining matching attempt
  evidence, terminalize the command separately as `failed`, `cancelled`, and `expired`, then commit a
  late verifiable acknowledgement before and after restart. Each source state promotes exactly once to
  absorbing `provider_accepted`, retains later history and uncertainty, and starts no attempt; an
  unmatched, unverifiable, ambiguous, or non-acceptance callback is a terminal no-op. Repeat while
  upgrade quiescence retains the matching attempt and through each projection path. Crash a worker
  immediately after its longest persisted dispatch lease is committed; preparation waits through that
  lease's exact expiry and bounded fence recovery, or reaches the frozen failure deadline without an
  eligibility watermark. Start preparation at every backup publication/reconciliation phase: new
  `backup.create` is rejected, the admitted coordinator must converge to one terminal state, and its
  final SQLite/filesystem truth precedes the stable source heads. No prepare watermark or rollback
  eligibility may appear until the store proves all invocations and leases quiescent, all fenced truth
  committed, and no backup coordinator nonterminal; a blocked or unprovable bound yields
  `upgrade_quiescence_unproven` without an old snapshot rollback offer. Force that failure by longest-
  lease overrun and by a clock hold, then crash before/after terminal failure commit: startup restores
  the exact prior operator-admission intent, removes only upgrade-quiescing holds, preserves stricter
  holds/leases, and requires a fresh-key prepare after ordinary recovery. Make an admitted backup's
  durable execution deadline the maximum term and prove prepare snapshots that exact proof and does not
  fail early. Kill repeatedly before and after
  every component deadline; startup reuses the persisted safe-UTC deadline/component evidence,
  reconstructs its monotonic remainder conservatively, and never extends it. In the rollback-eligible window,
  try
  every cataloged selected-state mutator and each autonomous expiry/purge/cleanup/scheduler/lease/outcome
  transition; each remains frozen or returns `upgrade_activation_pending`. Crash through clock settlement
  and shutdown evidence before and after migration finalization, hold smoke beyond at least one checkpoint
  interval, and crash every `clock.checkpoint` journal publication and SQLite-mirror prefix. Run the
  same held smoke for many tail-fold cycles under a deliberately tiny test cap: the complete
  checkpoint-plus-tail image stays bounded while its ordered transcript commitment and projected
  upgrade state remain exact. The three-record lifecycle registry and upgrade automaton remain the only
  inputs to that authenticated projection under activation/rollback serialization. Both explicit acknowledgement and automatic settle
  through an event-triggered checkpoint write only clock authority plus `deadline_derivation_pending`;
  prove no message/circuit/scheduler deadline changes before activation,
  rollback clone selection, and forward-repair hold-clear each derive the same conservative result in
  every anomaly-held row with a null deadline in the selected generation before effects resume.
  Close operator admission before each successful activation, rollback, and forward-repair path.
  Activation and forward repair preserve its exact complete address, actor, reason, and changed time;
  rollback preserves the selected value/actor/reason/time but installs the fresh branch incarnation at
  generation one with a null receipt. Every path clears only upgrade-specific holds, and a fresh submit
  stays rejected until explicit `admission.set open`. Cross
  exact SQLite and fixed-root command-expiry boundaries during long smoke: result/reservation authority
  ends through a durable monotonic high-water proof without a forbidden selected-state mutation, inert
  bytes remain rollback-safe, and every selected hold-clear path prunes them before same-key fresh-
  effect admission. Let another boundary cross without any lookup, then invoke activation, rollback,
  and forward repair: each must first checkpoint/mirror and restart its checkpoint/tail projection proof or fail
  unavailable without deletion, disclosure, pointer change, or hold clear. Enter a later clock anomaly
  before pruning and prove the old authority does not revive. Crash through migrate/activate/rollback
  journal phases, exact target-certificate validation, and pointer barriers. Inject a missing or
  inconsistent checkpoint/tail projection, forbidden authenticated record, and unexpected transaction/watermark change; each
  creates fixed-root `upgrade_diverged` provenance and proves rollback, activation, and involved-generation
  deletion fail closed rather than erase it. Separately corrupt a journal HMAC/sequence and prove the
  original bytes remain untouched under a stronger fixed-root integrity hold. Normal activation cannot
  clear either condition. Exact-digest
  `forward_repair` preserves the selected state only after full invariant checks, records an auditable
  resolution, and permanently removes snapshot rollback eligibility. No path can later select an older state
  generation that loses a credential revocation, purge/tombstone, issued secret, command reservation,
  accepted command, or effect. Rollback creates and activates a fresh logical clone of the sealed source,
  reconciles allowed fixed-root evidence, preserves the source untouched, and retains its command result
  in the fixed journal. Resolve a divergence, delete every named generation only after its ordinary
  dependency checks pass, advance durable safe time to just before, exactly at, and just after the
  frozen audit-support deadline, and fold at every replacement barrier. The poison/resolution pair
  remains before the half-open boundary and disappears only in the authenticated checkpoint at/after it;
  unresolved, unexpired, or still-generation-dependent provenance never disappears. Repeat enough
  divergence/repair/delete/horizon/fold cycles under reduced caps to exceed the production-ratio entry
  limit without retirement and prove the live projection remains bounded, crash-selecting exactly the
  old or new complete image.
- **AC-058 — API-only CLI boundary.** The client crate dependency graph excludes the store/SQLite
  crates, binary syscall tracing finds no state/config/key-ring access for every non-lifecycle command,
  and API/CLI cases remain set-equal to the frozen catalog.
- **AC-059 — Retriable bootstrap.** Kill bootstrap before and after every generation/pointer durability
  barrier and drop the committed response. Unselected staging generations remain inert and reclaimable;
  retrying the same command key either completes one activation or returns the same secret-free result.
  A valid pre-bootstrap recovery ring/journal is permitted; unrelated files, symlinks, or state
  generations fail closed. Every no-pointer phase is reconstructible from the fixed control journal.
- **AC-060 — Fixed-root journal and recovery-key crash safety.** Kill control-journal initialization,
  bootstrap/blank-restore/shutdown intent, and recovery-key generation/import/retirement at every
  intent/key/result, directory-fsync, and optional SQLite audit-mirror boundary. Recovery
  deterministically finishes or rolls back one operation, never exposes a partial key, never guesses a
  generation, and never makes a referenced key disappear. Include the boundary after durable
  one-time-secret consumption but before the first response byte; restart converges to visible,
  dependency-free `pending_escrow`, never reissues the secret, and permits explicit retirement. With a
  deliberately tiny journal cap, hold that pending successor across many periodic checkpoints and fold
  the tail repeatedly. Crash before/after every checkpoint-temp fsync, replacement rename, parent fsync,
  and subsequent retirement barrier. Bytes/entries and validation work remain within their exact caps;
  live command/reservation/ring authority survives every prefix; the reserved retirement/reconciliation
  transition always remains publishable. Fill ordinary projected capacity exactly, prove the next
  resource-creating operation returns `503 control_capacity` before intent/effect, then complete the
  already admitted worst-case transition and a capacity-reducing retirement from reserved capacity.
  With that ordinary capacity still full, execute more than 64 alternating exact-address clock-
  acknowledgement and process-shutdown cycles across response loss, fold, and restart; at every prefix
  there are at most four addressed-state cells, at most 60 other reconciliation-projection entries, and
  the next clock settlement, pending-escrow retirement, and key-independent terminalization remain
  publishable. Stale hold/process addresses conflict without reviving or repeating an older action.
- **AC-061 — Versioned route closure.** Router, authorization dispatcher, API client, CLI, and generated
  documentation are set-equal to the frozen catalog, including deployment probes. No unversioned
  health/readiness/metrics alias or second handler bypasses its operation descriptor. Literal routes
  precede parameter routes, including `/v1/admin/restores/current` over `{restore_id}`. Every catalog
  identity/method-path/CLI string and every normative `PR-*`, `AC-*`, `A-*`, and `INV-*` definition is
  unique. Maintenance readiness remains bounded and reports `transition_in_progress` from an atomic
  journal snapshot without acquiring the transition gate. Mutation checks reject disguised/duplicate
  definition IDs in either canonical document/form, every unknown top-level catalog field, every
  per-operation method/path/CLI/request-codec/response-codec/policy/binding/idempotency/risk/mode swap,
  and any fixed-root registry omission or addition. Independent mutations cover each frozen top-level
  scalar/key, required/unknown operation field, uniqueness constraint, codec use, canonical-ID
  deletion/renumbering/heading level/closing delimiter, and every advertised disguise. Strict top-level
  scalar types, document/catalog version linkage, structural parsing of the initial `Field`/`Value`
  metadata table under flexible GFM whitespace, exact metadata-field order/multiplicity/full-reference
  equality, maintenance-marker multiplicity/order/count, and internal upgrade-lifecycle-marker
  multiplicity/order/count, plus fixed-root addressed-state-marker multiplicity/order/count and its
  exact two-operation membership, and generation-guarded-marker multiplicity/order/count and its exact
  five-operation membership, are independently mutated;
  invalid element types or missing version keys fail with a bounded checker error rather than an
  uncaught exception. A separately DCO-preserved `specs/release-identity.toml` v1 manifest names exactly
  `specs/product.md` and `specs/architecture.md`, their declared versions, one closed canonicalization
  identifier, and their complete SHA-256 identities. Canonicalization converts CRLF or lone CR to LF
  and requires UTF-8 plus one terminal LF; it preserves every other byte, including blank lines,
  indentation, and trailing horizontal whitespace, so Markdown ownership cannot change invisibly.
  Missing, extra, duplicate, wrong-path, wrong-version, wrong-canonicalization, or wrong-digest entries
  fail closed. The manifest is frozen in a commit after specification/mutation RED and before checker
  implementation; changing a digest remains a reviewed process action, never semantic proof by hash.
  Direct cases exercise malformed metadata header/separator and later-table
  linkage fields disguised through emphasis, inline code, links, HTML, entities, comments, punctuation,
  case, escaped table punctuation, reference-style labels, image alt text, hidden inline content, and
  literal/numeric-entity RLO/PDF reversal. Every one of the 12 Unicode `Bidi_Control` code points is
  exercised in literal, decimal-entity, and hexadecimal-entity form for each linkage field; named LRM/
  RLM entities are additional cases. Raw document and complete-line caps run first. For input within
  those caps, bidi rejection occurs after one HTML-entity decode and before source-order, fence, HTML,
  or definition interpretation; an overlong line containing bidi therefore reports the line-cap reason.
  One bounded GFM fence tokenizer supplies line provenance to HTML masking,
  definition lint, and metadata lint. Before that classification, every complete source line is checked
  against the 8,192-character cap, including fenced content. The tokenizer rejects a backtick in a
  backtick-fence info string, recognizes
  the exact supported top-level, blockquote, list, and mixed-container continuations, limits ordered
  list markers to CommonMark's nine digits, and never masks a line after its container ends. A blank
  continues a non-top-level fence only when it carries that exact container continuation; an
  unprefixed blank ends a quote/mixed fence before later container re-entry. Valid
  fenced code remains literal, including metadata-shaped rows and
  complete definition-shaped examples; an unmatched inline-code delimiter never restores separately
  proven fenced lines to the HTML stream or crosses a blank, container, heading, thematic, fenced, or
  HTML-block boundary. Ordinary multiline inline code within one paragraph remains literal. Inline-code
  linkage labels in actual later-table cells remain
  rejection disguises. Raw HTML is interpreted under a CSS-free model over the complete document,
  capped at 1,048,576 source characters and 64 modeled open elements. The HTML pass performs no more
  than twice the length of its own masked/rendered input; each later pass is linear in its own bounded
  input. The parser retains one current visible run rather than one copy per open
  element, emits a new candidate run at every modeled `br`/`hr`/`wbr` or structural boundary, and
  requires every closing tag to match the stack top. Incomplete or crossed markup, multiline raw tags,
  comments, declarations, processing instructions, and hidden subtrees that can cross source-line
  candidate boundaries fail closed. Complete benign single-line comments, declarations, and processing
  instructions are accepted standalone but cannot split any linkage label. Case-folded duplicate attribute names, inline
  style/class/id/direction/popover, style elements, external stylesheet links, and context-sensitive
  visibility elements fail closed, while modeled script/template/`hidden`/`aria-hidden` subtrees
  contribute no visible prefix. One offset-preserving Markdown pass produces three distinct provenance
  channels: rendered bytes, raw-HTML-eligible bytes, and visible literal code/autolink/escape bytes.
  Only a grammatically complete link/image construct owned by one inline block may classify its title,
  destination, or reference label as non-rendered. The visible link/image label opener, its nesting,
  and its eventual closing bracket are owned by that same block: every inline-block boundary clears
  all pending label state before a later `]` is interpreted. A soft line break inside one paragraph
  retains label state. A destination contains no line ending; a reference label cannot cross its
  block; and a title may span lines but contains no blank line and remains inside its original
  paragraph. Invalid or block-crossing structure is restored as visible source before normative-ID
  classification. Escaped tag delimiters plus inline/fenced code and autolinks remain
  visible literals but can never open or close raw-HTML stack state. Markdown inline
  code and autolinks therefore remain literal rather than raw HTML;
  the normative-ID wrapper policy still rejects a complete inline-code definition shape, including in
  a one-line or source-split structural HTML cell through whole-document cell provenance. After HTML
  visibility extraction, NFKC output is capped at exactly 32,768 characters before every downstream
  default-ignorable/Markdown scan; the accepted boundary and next character are aggregate controls.
  Definition-like rendered prefixes/fragments are independently exercised for duplicate and unknown
  IDs across 24 plain/full/collapsed/shortcut/quoted/angle link, image, HTML, and emphasis wrapper forms,
  eleven contexts (bare paragraph, bullet, numbered, five GFM table encodings, blockquote, heading, and
  task list), and all four ID families. Structural prefixes are stripped before table parsing; an
  additional 5 table encodings × 5 blockquote/bullet/numbered/heading/mixed-prefix families × 8 IDs matrix closes
  their composition. A second 5 encodings × task/exact-64/exact-65 prefixes × 8 IDs matrix closes the
  task/depth composition. Escaped backticks never open code spans in the HTML visibility pass. A colon
  is a definition separator with or without a structural prefix. One bounded rendered-suffix scanner
  detects em-dash/colon definitions anywhere after the canonical core; an unwrapped period is never a
  direct suffix separator and enters only through an actual matched rendered delimiter or HTML run, so
  immediate and later ordinary `AC-001. This ...` references remain valid. A raw opener/closer token is
  not provenance: delimiter role, matching width, flanking, escaping, code/channel ownership, and the
  candidate ID's containment inside the matched span are all required. Backtick runs pair only with the
  next equal-width run under one noncrossing forward scan; foreign-width runs inside that code span stay
  visible literal content. Rendering removes only proven matched syntax markers, never unmatched or
  foreign-width delimiter bytes. It recognizes GFM section 6.5's
  isolated one- or two-tilde strikethrough delimiters without treating runs of three or more as
  strikethrough. The
  matrix crosses 24 wrapper forms plus eight inner-separator emphasis/visible-HTML/one-tilde forms over
  all five canonical owner forms (160 cases), in addition to the 20 plain/HTML-boundary cases. A
  separate four Markdown non-rendering/escape-context forms × five owners = 20 cases proves that a
  title, image title, angle destination, or escaped tag opener cannot create checker-only HTML state.
  A further 10 known/unknown owner IDs × seven inline link/image destination, reference-label, title,
  and angle forms × eight blank/heading/list/quote/thematic/fence/HTML block boundaries = 560 cases
  proves invalid inline syntax cannot mask a later visible definition. A separate four link/image,
  nested-label, three-title-delimiter, and reference-label forms × 10 owners × eight boundaries matrix
  opens visible label state in the prior block, closes it in the later block, and puts
  `<br>ID: Shadow definition.` in locally balanced non-rendered-looking syntax: all 320 cases must reject
  rather than invent a cross-block construct. One valid soft-line multiline link, one valid soft-line
  multiline image, each with a genuinely non-rendered title, and one broken cross-block label with
  ordinary prose are the three positive controls. The same block-boundary scanner expands tabs to
  four-column stops after list markers: stale inline-code and label state crossing each of `-\t`,
  `*\t`, `+\t`, and `1.\t` over ten known/unknown owners adds 80 rejected cases. Ordered `2.\t` and
  `9.\t` do not interrupt a paragraph and remain positive multiline code/label controls.
  A one- or two-hyphen Setext underline also terminates the prior inline block. For an interrupting
  unordered marker or ordered `1`, padding wider than four columns still starts a list and treats the
  excess as indented item content; it cannot preserve inline state into the following visible item or
  paragraph line. Two stale states × two short Setext forms plus three five-space bullets, three
  tab-over-padded bullets, and one tab-over-padded ordered-one form × ten owners add 180 rejected cases.
  Five-space and tab-over-padded ordered `2`/`9` forms add eight non-interruption controls. Four
  top-level/quoted/nested tab-padded list fences containing definition-shaped literal code are positive
  controls for the shared raw-offset-preserving fence-container scanner.
  A recognized GFM table is also an inline-ownership boundary: header and body rows are split into
  independent cells at raw unescaped pipe delimiters before inline code is parsed, and no label/image
  opener may cross a cell, row, or table exit. Four link/image/nested/title/reference forms × ten
  owners × six header/body cell/row and code-pipe transitions add 240 rejected cases. An ordinary
  non-table pipe, an escaped table-cell pipe, an incompatible code-pipe header/delimiter pair, and
  complete titles owned by one header or body cell add five positive controls.
  Root code indentation is not a table, but indentation inherited from an active list container may
  leave less than four spaces at the table block parser. Table ownership therefore uses container-
  relative indentation. Four link/image/nested forms × ten owners × loose bullet, loose ordered,
  quoted-bullet, and nested-bullet header/body cell/row contexts add 160 rejected inherited-list cases;
  table-looking source after an explicit root paragraph boundary and then four-space code indentation,
  plus a complete inherited-list header-cell title, add two positive controls.
  CommonMark tabs advance to four-column stops. A tab after a bullet or ordered marker may establish a
  live list content indent, and continuation indentation may itself contain tabs; table ownership uses
  a bounded tab-expanded view while preserving exact raw-source offsets. Four link/image/nested forms ×
  ten owners × four tab-padded-marker, four tab-indented-continuation, four nested partial-dedent,
  one quoted inherited-body-row extent, plus one lazy body-row context add 560 rejected cases. A tab-indented table-looking
  block at the document root remains literal code, while complete titles owned by one cell of a tab-
  padded-marker table and one cell of a tab-indented-continuation table remain non-rendered; all three
  are positive controls.
  A second full-reference label is not presumed non-rendered merely because its brackets are locally
  balanced: without a matching reference definition, GFM renders the complete source literally. The
  alpha checker's raw-HTML provenance channel therefore retains second-label bytes instead of granting
  hidden provenance without resolution. Its separate visible-label normalizer may elide the reference
  suffix to isolate the rendered primary label, but that elision never masks HTML from the provenance
  channel. Four link/image/nested forms × ten owners × bare, bullet, table-header, and table-body
  contexts add 160 rejected unresolved-label cases; ordinary unresolved link and image labels add two
  positive controls.
  Sixteen matched, escaped,
  closer-only, asymmetric-tilde, and code forms × five owners = 80 positive controls prove an ordinary
  period reference outside an unrelated delimiter span remains valid. Two noncrossing/foreign-width
  code compositions plus six visible unmatched emphasis/tilde prefixes inside an HTML run × five owners
  add 40 matched-syntax positive controls. These 120 delimiter controls plus the three general label-
  ownership controls and five table-ownership controls remain outside rejected arithmetic.
  Period-form wrapper provenance
  crosses all 25 attribute-free visible inline HTML elements over the five owners plus three nested,
  hidden-prefix, and inline-code-prefix compositions per owner (140 cases). Combined Markdown-wrapper
  and outer-HTML provenance is capped at 256 candidates per canonical line before suffix rendering;
  the exact boundary passes and candidate 257 fails closed. Later
  metadata strips the same bounded structural and list-task prefixes before table splitting and crosses
  three linkage fields × five table encodings × twelve prefix/task forms = 180 cases. The document/
  version subtotal is exactly 385: 13 direct initial/linkage + 18 duplicate-row + 54 disguise + 180
  structural/task-prefix + 6 single-line declaration/
  processing-instruction + 114 complete-property bidi cases. The definition subtotal is independently
  reconstructable as exactly 6,243: 35
  direct cases (eight disguises; 4 families × duplicate/deletion/renumber; three canonical
  missing-closing-bold forms; two A-heading levels; six appended unclosed forms; and four parser-bound
  mutations), 24 wrappers × 11 contexts × 8 known/unknown family IDs = 2,112, nine Unicode characters ×
  two bullet/table contexts × 8 IDs = 144, two reversed bidi encodings × three contexts × 8 IDs = 48,
  plus 12 controls × 3 encodings × 8 IDs and two named entities × 8 IDs = 304 complete-property cases,
  two Setext levels × 8 = 16, two nested list/blockquote forms × 8 = 16, three bullet/blockquote/heading
  colon forms × 8 plus ten known/unknown bare-colon owner forms = 34, four structural-HTML forms
  (heading, table, multirow table, multiline cell) × 8 = 32, the five
  unordered/ordered empty/lower/upper task-marker states left after the matrix's unordered-lower
  baseline × 8 = 40, 33 CSS/intrinsic/contextual/duplicate-attribute/unmodeled-element visibility
  prefixes × 8 = 264,
  the 200 structural-prefix/table compositions, 4 multiline-HTML forms × 8 = 32, eight escaped-code-
  delimiter/HTML compositions, 5 canonical line forms × 4 plain/`br`/`hr`/`wbr` trailing-definition
  separators = 20, the 160 rendered-suffix wrapper, 140 visible-HTML period-wrapper, and 20 Markdown-
  context cases, 6 modeled HTML boundaries including hidden/
  ARIA-hidden break attributes × 10 IDs = 60, two invalid fence/container forms × 10 IDs = 20, two
  terminated quote/mixed-container forms × 10 IDs = 20, eight malformed/depth HTML cases, two inline-
  code structural-cell forms × 8 IDs = 16, eight unmatched-inline/block-boundary forms × 10 IDs = 80,
  two stale inline-code/label forms × four tab-padded interrupting markers × 10 IDs = 80,
  two stale forms × nine short-Setext/over-padded-list boundaries × 10 IDs = 180,
  5 table encodings × 3 task/depth prefixes × 8 IDs = 120, the 560 block-crossing link-context cases,
  4 link/image/nesting/title/reference forms × 10 known/unknown owners × 8 block boundaries = 320
  block-crossing visible-label cases,
  4 link/image/nesting/title/reference forms × 10 known/unknown owners × 6 GFM table cell/row and
  code-pipe transitions = 240 table-ownership cases,
  4 link/image/nesting/title/reference forms × 10 known/unknown owners × 4 inherited-list table
  contexts = 160 container-relative table-ownership cases,
  4 link/image/nested-title forms × 10 known/unknown owners × 14 tab-padded-marker/tab-continuation/
  partial-dedent/inherited-extent/lazy-row list table contexts = 560 tab-stop-aware table-ownership cases,
  4 unresolved link/image/nested-reference forms × 10 known/unknown owners × 4 paragraph/list/table
  contexts = 160 visible unresolved-reference-label cases,
  10 known/unknown owner IDs × three separators = 30 single-cell pipe definitions, one ordered-start-1
  paragraph-interruption case, one complete-document bound case, one post-NFKC bound case, and one
  trailing-provenance candidate-bound case. A literal outer-pipe paragraph yielding one rendered cell
  is classified for a leading definition without changing real multi-cell table behavior. Only an
  ordered marker starting at 1 interrupts a paragraph; established list containers retain every valid
  1–9-digit marker. The exact family equation is
  `35+20+160+140+20+560+320+240+160+560+160+30+1+2112+40+144+352+16+16+200+34+32+264+32+8+60+20+20+8+16+80+80+180+120+1+1+1 = 6,243`.
  Exact 8,192/8,193 fenced and non-fenced line, 64/65 structural and HTML-depth,
  1,048,576/1,048,577 document, and 32,768/
  32,769 normalized boundaries, linear scanner work, ordinary canonical-line references, valid owned-
  blank container fences, fenced metadata, and genuinely visible benign HTML/code/autolinks are
  positive assertions and do not inflate the rejected count. Every rejected callback enters
  `check_all` exactly once at runtime; all 78 static call sites name a narrow expected reason class.
  Independently asserted family subtotals prevent an unrelated checker exception/error class or a
  disconnected aggregate stage from passing. The complete arithmetic is 1,476 operation + 30 catalog +
  385 document/version + 6,243 definition + 7 maintenance + 7 lifecycle + 7 addressed-state + 7
  generation-guarded + 23 complete-revision + 66 incarnation-allocator + 27 upgrade-exit-capacity + 12
  release-integrity + 12 evidence-parity = 8,302
  rejected mutations;
  the harness fails if any family, category, runtime-entry count, or total differs.
- **AC-062 — Restore lineage isolation.** Attempt same-instance proven-ancestor, blank-state, sibling,
  foreign-instance, missing-provenance, and forged-provenance restores. Only the proven ancestor may
  compare/replay current tombstones; blank state reports comparison unavailable, and every nonempty
  unproved replacement fails before activation. Kill every blank-state upload/journal/finalization/
  pointer/response prefix; same-key retry converges to one result without guessing a generation. Build
  a report above the 256-KiB one-response limit, page every immutable entry under one digest with no
  omission or cross-report cursor reuse, and resume only with that exact digest. On a blank host,
  unknown secret-reference names fail before activation; pre-provisioned known names with absent values
  produce connector holds while the fresh recovery interface remains available. Race the root
  provisioner against both daemon modes and prove it fails to acquire the shared owner lock rather than
  replacing a catalog generation beneath validation. Give two supported sibling descendants internally
  valid suffixes and prove neither suffix can authenticate as the other's selected history epoch.
- **AC-063 — Command-key and addressed-state ledgers.** Derive every `command_key` and
  `one_time_secret` operation from the frozen catalog and test same/different actor, key, body, phase, response loss, restart, concurrent
  execution, key-version retirement, a null nonterminal expiry, and the exact terminal half-open expiry
  boundary. Each authoritative
  SQLite effect and safe result commits atomically in one generic ledger; every fixed-root equivalent
  converges through the journal and its portable reservation index. Foreign restore carries the
  encrypted reservation MAC generations plus unexpired/null reservations, including pre-bootstrap
  commands, and same-key reuse returns
  `command_namespace_changed` without a new effect. Recovery-key acknowledge is the only allowed
  different-body same-key phase transition, while single-phase API-key issue/rotation never invent an
  acknowledgement action. Hold a generated resource/artifact beyond terminal command expiry and prove
  same-key reuse creates one new command while the old generated-resource dependency remains intact.
  During rollback-eligible smoke, cross the exact expiry for both SQLite and fixed-root records: lookup
  first makes any newly observed crossing durable through the allowed safe-time checkpoint/mirror,
  then stops disclosing/reserving without changing the frozen selected-state watermark. Enter a later
  clock hold and restart before physical pruning; proven-expired result, conflict, namespace, and
  portable reservation authority never reappear. Activation, rollback, and forward repair each prune
  selected authority before effects resume, after
  which same-key reuse creates exactly one fresh command while immutable audit bytes remain inert.
  Separately, advance the surviving fixed-root high-water beyond domain-idempotency, generic-command,
  foreign-namespace, and local/portable fixed-root boundaries while an older proven-ancestor artifact
  still contains their physical rows. Restore that artifact and crash every target high-water carry,
  reconciliation, pointer, hold, and resume prefix: old authority never reappears, and same-key reuse
  remains a blocked fresh-effect attempt until the restore hold clears, then creates at most one new
  command.
  Disconnect during every streaming/fixed-root input phase, discard the caller key, and without
  restarting submit a new fixed-root mutator: the coordinator finishes a self-contained prefix or
  safely rolls back/terminalizes missing-input work, releases the gate, and never repeats an effect.
  Independently derive exactly `clock.acknowledge` and `system.shutdown` as `addressed_state`; prove
  neither accepts a command envelope or emits `command_expires_at`/portable reservation, and no third
  operation can use the class. Cross exact current, exact most-recently-completed, stale, future, and
  mismatched hold/process addresses with different actors, response loss, concurrent repetition,
  restart, a newer hold/process, and current-authorization removal. Only an authorized newest current/
  completed address returns its one safe phase/result, no effect repeats, and four fixed cells bound the
  projection independently of request count.
- **AC-064 — Restore comparison retention.** Create backups at multiple watermarks, continue accepting
  and effecting commands, purge payload and age ordinary message/audit metadata, and exercise cleanup at
  every support-deadline boundary. Every unexpired proven artifact has a gapless digest-chained batch
  suffix and a complete immutable report; cleanup cannot advance the coverage anchor past its batch
  head. Delete or alter a sole, middle, final, header, or event row without updating the authenticated
  chain and the nonempty restore fails before activation. An expired, unsupported, or deliberately
  gapped nonempty-state replacement is likewise rejected. The same cryptographically valid artifact
  remains eligible on a blank host after `nonempty_restore_supported_until`, with comparison explicitly
  unavailable and every integrity/key-closure/quarantine/held-resume control unchanged. Transplant an entirely valid recomputed sibling suffix and live head, then
  inject missing, extra, changed, and wrong-epoch tombstones before and after the artifact watermark;
  authenticated epoch/path plus exact artifact-base-union-suffix projection validation rejects each
  before report construction.
- **AC-065 — Handler deadline truth.** Race every mutation class at mailbox-full, queued, atomic
  queued-to-started, transaction-started, committed, result-delivery, and client-disconnect boundaries.
  A returned `408` proves the actor observed and skipped a cancelled queue entry. Once started, the
  handler returns the authoritative bounded result or `operation_outcome_unknown`; same-key/idempotent
  retry finds at most one effect, and no late commit follows a definite pre-commit response. For each of
  the five generation-guarded operations, drop an effect and no-op response after every commit/
  publication/wake boundary, restart, and recover the exact current result by its complete incarnation/
  generation address. Then commit its opposite transition and retry the original request through API
  and CLI: it returns
  `state_generation_conflict` with no mutation, no revived credential/grant, and no reopened admission.
  Repeat after an ABA back to the original value, an unrelated same-resource generation advance, and
  same/different-actor retries; disable/descope the original actor before exact receipt recovery and
  prove disclosure is denied, while a different currently authorized actor conflicts. Lose a same-
  value no-op, then submit a different desired value under the still-current complete pair: it is one
  deliberate fresh mutation, while retrying the old no-op remains effect-free. The fixed receipt count
  remains independent of invocation count.
  For every guarded operation, take a backup before the request, lose the post-backup response, restore
  or rollback to a new branch, deliberately reauthorize the same stable actor, resume, and retry after
  restart. The old incarnation always conflicts even when its numeric generation and desired/current
  values collide and every unrelated non-key injected ID/random source repeats. On a blank-host restore from an
  artifact predating an abandoned descendant, the locally derived namespace and intent-burned serial
  still make the old complete address conflict. Reject any request/artifact field that attempts to
  choose the target namespace, serial, or incarnation. For admission, repeat a lost same-state no-op across fresh `drain.start`, both
  `complete` and `timed_out` terminal outcomes, response loss, and restart; accepted drain advances the
  admission generation and clears its receipt before creating the coordinator, so the old retry cannot
  reopen it.
  Inject `u64::MAX - 1` and `u64::MAX` for admission, principal, and grant resources. At `MAX-1`, each
  applicable guarded mutation and every non-guarded writer (`drain.start` and `principal.update`)
  commits exactly once to the maximum. At `MAX`, exact receipt/no-op/command recovery stays effect-free,
  while every fresh writer returns `state_generation_exhausted` before changing resource, receipt,
  authorization epoch, audit, command row, drain coordinator, or readiness detail. Exercise both 32-
  bit storage-limb carry boundaries. API and CLI parity rejects missing, malformed, wrong-width, stale,
  future, or branch-old incarnation and generation components and accepts only the exact current pair.
- **AC-066 — Authenticated history branch.** Create a common backup ancestor, diverge through supported
  restore/rollback boundaries into two epochs, continue effects and purges on both, and attempt every
  whole-suffix/head/tombstone transplant. The fixed-root-authenticated selected epoch, typed parent path,
  and purge-event projection admit only the actual selected branch; crash every epoch/pointer journal
  barrier and restart into one coherent epoch/generation pair. At fixed-root initialization inject an
  entropy error, short fill, all-zero key sample, and identical journal/portable key samples; each fails
  before a usable key, journal intent, state generation, or pointer exists. Across bootstrap, restore,
  and rollback, repeat every unrelated non-key random/ID output and prove the structured incarnation still
  advances exactly once. Force parent, retained-sibling, abandoned-intent, and staged-history target
  reuse or target/serial mismatch: each fails in bounded work before finalization/pointer mutation, the
  prior generation remains selected, and retry of the same durable intent reuses one target rather than
  rerolling. Exercise branch serial one, carry, `u64::MAX - 1`, and `u64::MAX`; exhaustion returns a
  safe `state_incarnation_unavailable` result without wrapping, staging, or selected-state change.
  Combine maximum with exact command recovery, a forbidding restore/upgrade hold, and a transition
  permitted through its own hold plus `clock_hold`; prove the documented total precedence and that no
  hold or allocator state is cleared.
  Fill the fixed-root ordinary capacity at serial maximum and prove allocator validation wins before
  capacity and clock without publishing an intent; with a usable next serial, no clock hold, and full
  capacity, prove `control_capacity` wins without a burn. With usable serial headroom, a nonterminal
  drain, and a pure clock hold, fresh `upgrade.prepare` returns `clock_hold` before drain/capacity
  disclosure in both actor orders and changes no allocator, binding, coordinator, or drain state.
  Replace the authenticated journal with an older valid image
  while retained pointer/history metadata carries a higher serial and require startup corruption hold
  before selection. Separately replace it with an equal-high-water image missing only the reconstructable
  terminal transition record; journal-behind-pointer recovery converges without authority loss,
  safe-time regression, or duplicate burn. Fold tail into checkpoint while an allocating intent is nonterminal and crash at
  every temporary-write, file-fsync, rename, and parent-fsync boundary; recovery must retain one exact
  high-water/target pair and never burn twice. Exercise the documented blank-root disaster-restore
  path from an exhausted owner root and prove nonallocating operations on the old root remain available.
  The artifact head may use a foreign namespace and serial `u64::MAX`; retain it only as authenticated
  immutable ancestry while selecting the independently keyed new root's serial-one target. Inject the
  same foreign epoch into the selected pointer, any guarded-resource incarnation, a locally issued
  intent target, local allocator provenance, or staged target and require corruption hold before
  selection. Crash and fold at every intent/staging/finalization/pointer barrier with that foreign parent
  and prove recovery reuses exactly one local serial. Back up that restored root, restore its artifact
  again onto a third independently keyed blank root, and repeat startup, fold, and anchor compaction;
  every artifact-internal boundary remains verified foreign ancestry and never becomes local authority
  or high-water evidence. At serial exhaustion, assert
  `incarnation_exhausted` across API, CLI, and metrics; delivery, authorized status, exact command/result
  recovery, and every continuation remain available subject only to their independent rules, while all
  allocating operations fail without burn. At branch serial MAX, `upgrade.prepare` fails before a
  coordinator or hold; at MAX−1 it may prepare, and rollback burns MAX exactly once with recoverable
  same-command truth. Run migrate → rollback burn → authenticated mismatch → divergence → forward
  repair at exact reserved capacity, and reject an incompatible successor journal framing/key-format
  version before any role is consumed. Combine one guarded resource at generation MAX with branch
  serial MAX and prove
  both closed readiness reasons remain observable while CLI guidance names only the independently keyed
  new-root recovery path, never an unavailable fresh branch on the exhausted root.
- **AC-067 — Fixed-root safe time.** Before bootstrap and with selected state, commit a terminal
  destructive command, lose its response, stop both modes, jump RTC beyond its expiry, and start
  maintenance. The authenticated fixed-root safe-time marker creates a hold; same-key retry returns the
  retained result and a fresh key, an apparently expired key, and every expiry-bearing submission remain
  blocked until explicit safe-time settlement, never repeating the effect. Read the exact hold-
  generation/observation address and crash clock acknowledgement after fixed-journal settlement but
  before the SQLite mirror: restart preserves the stricter authority, and exact addressed-state retry
  completes the mirror without performing cleanup or another effect; a stale/different address
  conflicts. Let healthy
  periodic checkpoints keep the authenticated marker current while total runtime exceeds the plausible-
  downtime ceiling and prove no false hold. Separately fault checkpoint publication at a fixed marker:
  injected startup wall time exactly at the allowed ceiling does not hold, while the smallest
  representable increment beyond it does; injected runtime wall/monotonic deltas exercise the same
  just-inside, exact, and just-outside configured step-threshold boundaries. The failed checkpoint bytes
  remain fixed, and only the precisely crossed boundary creates the observable hold.
- **AC-068 — Interrupted input terminalization.** Disconnect or time out bootstrap/restore/config input
  before body completion, after verified staging, and at every later journal phase; discard the original
  command key and keep maintenance running. In-process reconciliation either finishes from durable input
  or removes only its safe staging and terminalizes `input_abandoned`; another key can then proceed
  immediately, while the old key returns its bounded terminal result through expiry.

## P-18. Release acceptance

### P-18.1. First public release definition of done

- The first published pre-release uses Cargo package version `0.1.0-alpha` and an annotated Git tag
  whose exact name is `0.1.0-alpha` on the clean release commit.
- All first-slice requirements have traceable automated tests and no unresolved blocking lens finding.
- A maintained requirement-to-contract-to-test-to-evidence matrix marks every normative first-slice
  requirement; no unclassified `MUST` can silently fall outside release scope. CI first rejects a
  duplicate normative ID, catalog ID, method/path, or CLI command so evidence mapping is injective.
- The complete Rust quality/security gate passes twice from a clean checkout.
- Dependency, secret, source, container/artifact, and API security checks have recorded results.
- Agentic exploratory tests cover trust boundaries and operational recovery without editing frozen
  acceptance tests.
- Linux installation, restart, rollback, backup/restore, and real ntfy proof are recorded on Sol.
- Documentation distinguishes Contracted, Implemented, Proven, and Planned provider/platform claims.
- The public repository contains license, DCO, contribution, security, governance, and release metadata.

## P-19. Adjudicated product decisions

1. API-key principals and lifecycle ship in the first slice because remote simple authentication is a
   product requirement. Every TCP request authenticates; TCP remains disabled by default, and Sol
   proves it behind a VPN-bound trusted TLS proxy only after local proof.
2. Idempotency defaults to seven days, is configurable, returns its exact expiry, and requires evidence
   retention for the whole window. Clients needing a longer retry horizon configure it explicitly.
3. Failed payload retention defaults to 24 hours so dead-letter replay is operational; privacy-sensitive
   connectors can select zero. The product states logical-deletion and old-backup limits honestly.
4. The first slice uses API/CLI validation plus maintenance activation and controlled restart, not live
   configuration reload or direct operational-file replacement.
5. Reference capacity is a hard regression floor under the stable-storage contract, never a reason to
   weaken durability.
6. Replay takes an operator request-idempotency key, generates a new message identity, preserves the
   original owner, and records operator actor plus causal link.
7. Provider discovery is first-slice behavior. The generic HTTP API/webhook driver is designed now but
   remains Planned until its own conformance, threat-model, and live-proof gate promotes it.
8. API and CLI are peer access surfaces for every product capability. One operation registry and its
   parity gate prevent either surface from becoming privileged or incomplete; the CLI never bypasses
   authorization or opens SQLite.
9. Restore treats every credential and provider grant from the artifact as untrusted until a fresh
   maintenance-peer recovery operator deliberately re-establishes it; no restored remote key can
   clear the delivery hold.
10. Backup artifacts encrypt bundled state-key generations under a separately escrowed recovery key;
    key lifecycle is itself paired API/CLI functionality and lost escrow is an explicit restore failure.

## P-20. Glossary

- **Accepted by MsgRiver:** durably recorded locally; no provider claim.
- **Provider accepted:** provider acknowledged an invocation; not proof of recipient receipt/read.
- **Ambiguous outcome:** an external effect may have occurred but MsgRiver cannot prove the result.
- **Dead letter:** terminal failure evidence, optionally retaining sensitive payload for bounded replay.
- **Delivery:** generic process term; public status uses the more precise states above.
- **Durable:** crossed the P-07.1 stable-storage barrier and survives its supported crash model after
  success is returned; it is not a zero-RPO disaster-recovery claim.
- **First slice:** the complete initial vertical product contract in P-05.1, not a throwaway MVP.
- **Principal:** stable named identity used for authorization, ownership, limits, and idempotency scope;
  peer mappings and rotatable keys are credentials bound to it, not the identity itself.
- **Provider registration:** safe client-visible delivery capability backed by an operator-private
  connector; it exposes schemas and limits, never endpoint or credential configuration.
- **Replay:** creation of a new command causally linked to terminal prior work.
