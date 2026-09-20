//! MsgRiver core RED suite (layer 2): atomic behavior cases plus the structural
//! harness self-tests that prove the substrate is correct. Behavior cases fail at
//! their registered initial scaffold frontier until the implementation slice
//! removes each gap; the harness self-tests pass at RED.

mod cases;
mod clock_checkpoint_transition;
mod harness;
mod s11_allocator;
mod s11_canon;
mod s11_classify;
mod s11_incarnation;
mod s11_readiness;
mod s11_ring;
mod s11_safetime;
mod s11_state;
mod s11_surface;
mod safetime_high_water;
mod selftest;
