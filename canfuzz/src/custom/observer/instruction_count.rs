//! Observer for tracking IC instruction counts during fuzzing.
//!
//! This module provides the [`InstructionCountMap`] type, which stores instruction count
//! state, and the [`InstructionCountObserver`] type alias for use with libafl's observer
//! framework. The global [`INSTRUCTION_MAP`] is updated by
//! [`FuzzerOrchestrator::set_instruction_count`](crate::orchestrator::FuzzerOrchestrator::set_instruction_count)
//! after each canister execution.

use crate::libafl::observers::value::RefCellValueObserver;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

/// Tracks the instruction count state for the current fuzzing campaign.
///
/// - `max_instructions`: the highest instruction count observed so far.
/// - `current_instructions`: the instruction count from the most recent execution.
/// - `increased`: whether the most recent execution set a new maximum.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct InstructionCountMap {
    pub max_instructions: u64,
    pub current_instructions: u64,
    pub increased: bool,
}

/// Global mutable state for instruction counting, shared between the harness and observer.
pub static mut INSTRUCTION_MAP: RefCell<InstructionCountMap> = RefCell::new(InstructionCountMap {
    max_instructions: 0,
    current_instructions: 0,
    increased: false,
});

/// A libafl observer that reads from [`INSTRUCTION_MAP`] via a `RefCell` pointer.
pub type InstructionCountObserver<'a> = RefCellValueObserver<'a, InstructionCountMap>;

/// The name used to register the observer with libafl's observer tuple.
pub const INSTRUCTION_COUNT_OBSERVER_NAME: &str = "InstructionCountObserver";
