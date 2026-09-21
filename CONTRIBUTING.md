# Contributing to MsgRiver

Thank you for improving MsgRiver. Please discuss material behavior or architecture changes in an
issue before implementation, then update the living specification in the same change.

## Contribution contract

- Contributions are licensed under MIT.
- This project uses the [Developer Certificate of Origin](DCO.txt), not a CLA.
- Sign every commit with `git commit -s` to add a `Signed-off-by` trailer.
- Never commit credentials, private recipient data, or real message payloads.
- Keep tests hermetic; the normal test suite must never contact a public network.

## Development flow

1. Read `AGENTS.md`, `specs/product.md`, `specs/architecture.md`, and the active task.
2. For new behavior, write and demonstrate the relevant test slice RED first.
3. Commit the RED tests before production implementation.
4. Implement without weakening the frozen contracts.
5. Run the repository quality gate twice and attach relevant live-smoke evidence separately.

Small documentation corrections do not require a RED test. Security reports follow
[SECURITY.md](SECURITY.md).
