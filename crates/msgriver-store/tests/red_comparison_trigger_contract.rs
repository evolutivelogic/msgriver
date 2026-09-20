//! Frozen RED contract for the source-owned restore-comparison trigger slice.

#![forbid(unsafe_code)]

use msgriver_store::Store;

#[test]
fn comparison_selected_state_contract_is_explicit_in_v2_sql() -> Result<(), String> {
    let catalog = Store::selected_state_migration_catalog();
    let v2 = catalog
        .get(1)
        .ok_or_else(|| "COMPARISON-TRIGGER: v2 migration descriptor missing".to_owned())?;

    // This is intentionally a source-derived schema contract, not an actor
    // behavior test.  It freezes only constraints that SQLite can enforce
    // without identifying an actor transaction.
    for required in [
        "boundary_parent_origin TEXT",
        "CHECK(boundary_parent_origin IN ('selected_head', 'comparison_unavailable'))",
        "CHECK(lifecycle_event IN ('accepted', 'dispatch_marked', 'ambiguity_recorded', 'provider_accepted', 'failed', 'cancelled', 'expired', 'payload_purged'))",
        "CREATE TRIGGER restore_comparison_events_contiguous_before_insert",
        "CREATE TRIGGER meta_comparison_head_requires_complete_batch",
        "CREATE TRIGGER purge_tombstones_requires_payload_purged_event",
        "CREATE TRIGGER messages_insert_requires_accepted_comparison_event",
        "CREATE TRIGGER messages_terminal_state_requires_comparison_event",
    ] {
        if !v2.sql.contains(required) {
            return Err(format!(
                "COMPARISON-TRIGGER: required contract missing: {required}"
            ));
        }
    }
    if v2.sql.contains("restore_comparison_batches_no_delete")
        || v2.sql.contains("restore_comparison_events_no_delete")
        || v2.sql.contains("REFERENCES restore_comparison_events")
    {
        return Err("COMPARISON-TRIGGER: compaction-safe projection contract missing".to_owned());
    }
    Ok(())
}
