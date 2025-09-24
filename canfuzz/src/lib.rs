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
//! use canfuzz::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
//! use canfuzz::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
//! use canfuzz::libafl::executors::ExitKind;
//! use canfuzz::libafl::inputs::BytesInput;
//! use std::path::PathBuf;
//!
//! // 1. Define a struct for your fuzzer.
//! struct MyFuzzer(FuzzerState);
//!
//! // 2. Provide access to the fuzzer state.
//! impl FuzzerStateProvider for MyFuzzer {
//!     fn get_fuzzer_state(&self) -> &FuzzerState { &self.0 }
//! }
//!
//! // 3. Implement the fuzzing logic.
//! impl FuzzerOrchestrator for MyFuzzer {
//!     fn init(&mut self) {
//!         // Setup PocketIc and install canisters.
//!         println!("Canisters installed");
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
//!     let mut fuzzer = MyFuzzer(FuzzerState::new(
//!         "my_fuzzer",
//!         vec![
//!             CanisterInfo {
//!                 id: None,
//!                 name: "my_target_canister".to_string(),
//!                 wasm_path: WasmPath::Path("./my_canister.wasm".into()),
//!                 ty: CanisterType::Coverage,
//!             },
//!         ],
//!     ));
//!
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
