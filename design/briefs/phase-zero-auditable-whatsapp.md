# Design brief — Phase 0 auditable WhatsApp loop

**Status:** accepted direction — 2026-09-13

**Source:** `tasks/0173-product-direction-bidirectional-phase-zero.md`

## B-01 — Problem and outcome

An operator can send a high-value operational or application message through
an official WhatsApp sender, but cannot safely act on a reply unless the reply
is distinguishable from an unverified, duplicated or lost provider callback.

Phase 0 proves one complete, self-hosted loop:

```text
application submits message
  → MsgRiver records acceptance and sends through official WhatsApp
  → provider status is recorded
  → recipient replies in WhatsApp
  → MsgRiver verifies and deduplicates the callback
  → operator receives exactly one local ntfy alert with a safe reference
  → operator can inspect the correlated lifecycle
```

The outcome is not a chat product. It is evidence that one operational message
and its reply remain understandable after process restart and provider replay.

## B-02 — Users, jobs and boundaries

| User | Job to be done | Phase 0 result |
|---|---|---|
| Operator | Configure and recover one trusted communication route | Can diagnose the lifecycle without provider credentials or a hosted console |
| Client application | Request a bounded message without owning provider secrets | Receives an honest durable-acceptance result and later status lookup |
| WhatsApp recipient | Reply through the channel already used | The reply reaches the operator without a new portal or app |

The first reference user is the Sol operator running internal Evolutive Logic
applications. The recipient is a consenting participant who has initiated or
can receive the applicable official WhatsApp conversation. Phase 0 is a
reference deployment, not a claim of multi-tenant customer support.

## B-03 — Chosen interaction direction

**Direction A — operational loop without a new web UI (selected).** The
application uses the existing local/API submission surface; the operator uses
existing CLI/status/export operations and receives a compact ntfy alert. The
recipient stays entirely in WhatsApp. This is the fastest way to validate
value and preserves MsgRiver's single-operator character.

**Direction B — embedded inbox/dashboard (rejected for Phase 0).** It could
make conversations visible to a broader team, but introduces identity,
authorization, retained content, UX and multi-user product commitments before
the audit loop has proven value.

## B-04 — Observable journey and states

| Step | User-visible behavior | Required honest state |
|---|---|---|
| Submit | Client receives a durable message identifier or a bounded refusal | `accepted` is not provider delivery |
| Send | Operator can distinguish provider acknowledgement from later status | unknown external effect remains visible |
| Status callback | A delivery/read/failure callback extends the message lifecycle | callback provenance is recorded |
| Reply callback | A verified first reply produces one ntfy alert carrying only safe references | reply is correlated or explicitly uncorrelated |
| Duplicate callback | No second lifecycle event or ntfy alert is produced | duplicate is detectable in operator evidence |
| Restart/replay | The same callback still produces no duplicate alert | recovery outcome is inspectable |
| Invalid callback | No message/reply state changes and no recipient content is exposed | rejection is observable without logging secrets/content |

The ntfy notification is an operator signal, not a copy of the private message
body. The operator follows its safe reference through MsgRiver's local status
or export surface when more detail is needed.

## B-05 — Phase 0 acceptance

Chris can validate the design by watching a reference deployment complete this
scenario: submit an approved WhatsApp template, record `delivered`, reply from
the recipient, receive one ntfy alert, restart MsgRiver, replay the exact
provider callback, and observe no second alert while retaining the correlated
lifecycle evidence.

The design fails if it requires a dashboard, a second provider, an unofficial
WhatsApp bridge, caller-supplied endpoint/credential, or a claim that provider
delivery proves human receipt.

## B-06 — Deferred decisions

- The reference Meta Business account, phone number and template are external
  onboarding inputs; no secret or approval is assumed in source.
- Whether the first post-Phase-0 adapter is Telegram or email is a later
  evidence-led product decision, not an abstraction requirement now.

## B-07 — Approval boundary

Chris accepted this direction on 2026-09-13. It authorizes the Phase 0 product
contract and its later architecture, interface, behavioral RED and
implementation gates. It does not authorize a hosted service, a web inbox or
any second external channel.
