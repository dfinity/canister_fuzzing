//! A coverage-guided fuzzing framework for Internet Computer canisters.
//!
//! This framework is built on `libafl` and `pocket-ic` to find bugs,
//! vulnerabilities, and unexpected behavior in IC canisters by automatically
//! generating and executing a vast number of inputs. It supports both Rust and
//! Motoko canisters.
//!
//! ## Overview
//!
//! The core idea is to run canister code in a fast, deterministic, and
//! instrumented environment.
//!
//! - **Fuzzing Engine**: Uses `libafl` for
//!   state-of-the-art, coverage-guided fuzzing.
//! - **IC Emulator**: Uses `pocket-ic` to simulate the Internet Computer,
//!   allowing for fast, local execution of canister calls without needing a
//!   live network.
//! - **Instrumentation**: Canister Wasm is automatically instrumented with
//!   AFL-style coverage hooks. This allows the fuzzer to see which parts of
//!   the code are executed by an input and guide its mutations to explore new
//!   code paths.
//! - **Orchestration**: A simple trait-based system allows you to define the
//!   complete fuzzing harness, including canister setup and the logic for each
//!   test case.
//!
//! ## Key Modules
//!
//! The framework is composed of a few key modules:
//!
//! - [`fuzzer`]: Defines `FuzzerState`, which holds the `PocketIc` instance and
//!   information about all canisters under test.
//! - [`orchestrator`]: Defines the `FuzzerOrchestrator` trait. You implement this
//!   trait to create a fuzzing harness. The `run()` method handles the entire
//!   `libafl` setup and execution loop.
//! - [`instrumentation`]: Contains the logic to parse a Wasm file and inject
//!   coverage-tracking instrumentation. The `instrument_wasm_for_fuzzing`
//!   function is called during the `init` phase of your fuzzer.
//! - [`util`]: Provides helper functions, such as `read_canister_bytes` to load
//!   Wasm from a path, which can be specified directly or via an environment variable.
//!
//! ## Getting Started
//!
//! To create a new fuzzer, you need to implement the [`orchestrator::FuzzerOrchestrator`]
//! trait. This trait defines the setup, execution, and cleanup logic for your
//! fuzzing campaign.
//!
//! ```no_run
//! use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
//! use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
//! use canister_fuzzer::libafl::executors::ExitKind;
//! use canister_fuzzer::libafl::inputs::BytesInput;
//!
//! // 1. Define a struct to hold the FuzzerState
//! struct MyFuzzer(FuzzerState);
//!
//! // 2. Implement FuzzerStateProvider
//! impl FuzzerStateProvider for MyFuzzer {
//!     fn get_fuzzer_state(&self) -> &FuzzerState { &self.0 }
//! }
//!
//! // 3. Implement the main fuzzing logic
//! impl FuzzerOrchestrator for MyFuzzer {
//!     fn init(&mut self) {
//!         // ... setup PocketIc and install canisters ...
//!         println!("Canisters installed");
//!     }
//!
//!     fn execute(&self, input: BytesInput) -> ExitKind {
//!         // ... execute a canister call with the input ...
//!         let payload: Vec<u8> = input.into();
//!         println!("Executing input: {:?}", payload);
//!         ExitKind::Ok
//!     }
//! }
//!
//! // 4. The main function to set up and run the fuzzer
//! fn main() {
//!     let mut fuzzer = MyFuzzer(FuzzerState::new(
//!         vec![
//!             CanisterInfo {
//!                 id: None,
//!                 name: "my_target_canister".to_string(),
//!                 wasm_path: WasmPath::EnvVar("MY_TARGET_CANISTER_WASM_PATH".to_string()),
//!                 ty: CanisterType::Coverage,
//!             },
//!         ],
//!         "my_fuzzer".to_string(),
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
