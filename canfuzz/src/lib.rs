//! A coverage-guided fuzzing framework for Internet Computer canisters.
//!
//! This framework is built on `libafl` and `pocket-ic` to find bugs in IC canisters
//! by automatically generating and executing a vast number of inputs.
//! It supports both Rust and Motoko canisters.
//!
//! ## Getting Started
//!
//! To create a fuzzer, implement the [`orchestrator::FuzzerOrchestrator`] trait.
//! This trait defines the setup and execution logic for your
//! fuzzing campaign.
//!
//! ```no_run
//! use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder, FuzzerState, WasmPath};
//! use canfuzz::orchestrator::FuzzerOrchestrator;
//! use canfuzz::libafl::executors::ExitKind;
//! use canfuzz::libafl::inputs::BytesInput;
//! use std::path::PathBuf;
//!
//! // 1. Define a struct for your fuzzer and derive FuzzerState.
//! // Note: Requires the "derive" feature enabled for canfuzz.
//! #[cfg_attr(feature = "derive", derive(canfuzz::FuzzerState))]
//! struct MyFuzzer(FuzzerState);
//!
//! // Manual implementation if "derive" feature is not used:
//! #[cfg(not(feature = "derive"))]
//! impl AsRef<FuzzerState> for MyFuzzer {
//!     fn as_ref(&self) -> &FuzzerState { &self.0 }
//! }
//! #[cfg(not(feature = "derive"))]
//! impl AsMut<FuzzerState> for MyFuzzer {
//!     fn as_mut(&mut self) -> &mut FuzzerState { &mut self.0 }
//! }
//!
//! // 2. Implement the fuzzing logic.
//! impl FuzzerOrchestrator for MyFuzzer {
//!     fn init(&mut self) {
//!         // Setup PocketIc and install canisters automatically.
//!         self.as_mut().setup_canisters();
//!     }
//!
//!     fn corpus_dir(&self) -> PathBuf {
//!         PathBuf::from("./corpus")
//!     }
//!
//!     fn execute(&self, input: BytesInput) -> ExitKind {
//!         let payload: Vec<u8> = input.into();
//!         println!("Executing input: {:?}", payload);
//!         // Execute a canister call with the input.
//!         ExitKind::Ok
//!     }
//! }
//!
//! // 4. Set up and run the fuzzer.
//! fn main() {
//!     let canister = CanisterBuilder::new("my_target_canister")
//!         .with_wasm_path("./my_canister.wasm")
//!         .as_coverage()
//!         .build();
//!
//!     let state = FuzzerBuilder::new()
//!         .name("my_fuzzer")
//!         .with_canister(canister)
//!         .build();
//!
//!     let mut fuzzer = MyFuzzer(state);
//!     fuzzer.run();
//! }
//! ```
//!
//! For a complete example, see the `examples/` directory in the project repository.
pub mod fuzzer;
pub mod instrumentation;
pub mod orchestrator;
pub mod util;

mod constants;

pub mod custom;

// re-export libAFL and libAFL_bolts
pub use libafl;
pub use libafl_bolts;

#[cfg(feature = "derive")]
pub use canfuzz_derive::FuzzerState;
