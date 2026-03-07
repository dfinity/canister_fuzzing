//! Custom libafl components for canister fuzzing.
//!
//! - [`observer`]: Coverage map and instruction count observers.
//! - [`feedback`]: Instruction count maximization and OOM detection feedback.
//! - [`mutator`]: Candid-aware input mutation.

pub mod feedback;
pub mod mutator;
pub mod observer;
