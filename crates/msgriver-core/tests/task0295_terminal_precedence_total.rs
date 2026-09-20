//! Complete PR-087/A-09.1 terminal-precedence contract, frozen before Task
//! 0295 GREEN. The historical oracle target remains unchanged; this additive
//! table closes every resolved `TerminalGuards` tuple.

use msgriver_core::state::{TerminalGuards, TerminalWinner, terminal_precedence};

#[derive(Debug, Clone, Copy)]
struct PrecedenceCase {
    guards: TerminalGuards,
    winner: TerminalWinner,
}

const fn guards(
    known_provider_acceptance: bool,
    cancel_committed: bool,
    expiry_eligible: bool,
    attempt_exhausted: bool,
    late_verifiable_ack: bool,
) -> TerminalGuards {
    TerminalGuards {
        known_provider_acceptance,
        cancel_committed,
        expiry_eligible,
        attempt_exhausted,
        late_verifiable_ack,
    }
}

const TOTAL_PRECEDENCE: [PrecedenceCase; 32] = [
    PrecedenceCase {
        guards: guards(false, false, false, false, false),
        winner: TerminalWinner::NoTerminal,
    },
    PrecedenceCase {
        guards: guards(false, false, false, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, false, false, true, false),
        winner: TerminalWinner::Failed,
    },
    PrecedenceCase {
        guards: guards(false, false, false, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, false, true, false, false),
        winner: TerminalWinner::Expired,
    },
    PrecedenceCase {
        guards: guards(false, false, true, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, false, true, true, false),
        winner: TerminalWinner::Expired,
    },
    PrecedenceCase {
        guards: guards(false, false, true, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, true, false, false, false),
        winner: TerminalWinner::Cancelled,
    },
    PrecedenceCase {
        guards: guards(false, true, false, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, true, false, true, false),
        winner: TerminalWinner::Cancelled,
    },
    PrecedenceCase {
        guards: guards(false, true, false, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, true, true, false, false),
        winner: TerminalWinner::Cancelled,
    },
    PrecedenceCase {
        guards: guards(false, true, true, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(false, true, true, true, false),
        winner: TerminalWinner::Cancelled,
    },
    PrecedenceCase {
        guards: guards(false, true, true, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, false, false, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, false, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, false, true, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, false, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, true, false, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, true, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, true, true, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, false, true, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, false, false, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, false, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, false, true, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, false, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, true, false, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, true, false, true),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, true, true, false),
        winner: TerminalWinner::ProviderAccepted,
    },
    PrecedenceCase {
        guards: guards(true, true, true, true, true),
        winner: TerminalWinner::ProviderAccepted,
    },
];

#[test]
fn historical_precedence_vectors_remain_exact() {
    let historical_controls = [
        (
            "known provider acceptance beats cancel and expiry",
            guards(true, true, true, false, false),
            TerminalWinner::ProviderAccepted,
        ),
        (
            "known provider acceptance beats exhaustion",
            guards(true, false, false, true, false),
            TerminalWinner::ProviderAccepted,
        ),
        (
            "late verified acknowledgement promotes",
            guards(false, false, false, false, true),
            TerminalWinner::ProviderAccepted,
        ),
        (
            "committed cancel beats expiry",
            guards(false, true, true, false, false),
            TerminalWinner::Cancelled,
        ),
        (
            "expiry beats exhaustion",
            guards(false, false, true, true, false),
            TerminalWinner::Expired,
        ),
        (
            "exhaustion fails without a stronger guard",
            guards(false, false, false, true, false),
            TerminalWinner::Failed,
        ),
    ];

    for (name, guards, winner) in historical_controls {
        assert_eq!(terminal_precedence(guards), Ok(winner), "{name}");
    }
}

#[test]
fn terminal_precedence_is_total_for_every_closed_guard_tuple() {
    let mismatches: Vec<_> = TOTAL_PRECEDENCE
        .iter()
        .copied()
        .filter_map(|case| {
            let actual = terminal_precedence(case.guards);
            (actual != Ok(case.winner)).then_some((case.guards, case.winner, actual))
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "terminal precedence left {} of 32 closed guard tuples unresolved or wrongly ordered: {mismatches:#?}",
        mismatches.len(),
    );
}
