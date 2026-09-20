# Living specifications

MsgRiver uses one coherent corpus of living specs rather than one specification per increment.

- `product.md` owns product intent, requirements, scope, vocabulary, and behavioral acceptance.
- `architecture.md` owns interfaces, contracts, internal architecture, and the data model.
- `operations.toml` is the frozen independent source of every paired API/CLI capability.

The bootstrap task creates both documents and records independent reviews before any production code.
