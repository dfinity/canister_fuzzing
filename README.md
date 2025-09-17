# Canister Fuzzing Framework

A coverage-guided fuzzing framework for Internet Computer canisters, built on `libafl` and `pocket-ic`.

This framework is designed to find bugs, vulnerabilities, and unexpected behavior in IC canisters by automatically generating and executing a vast number of inputs. It supports both Rust and Motoko canisters.

## Overview

The core idea is to run canister code in a fast, deterministic, and instrumented environment.

- **Fuzzing Engine**: Uses [`libafl`](https://github.com/AFLplusplus/libafl) for state-of-the-art, coverage-guided fuzzing.
- **IC Emulator**: Uses `pocket-ic` to simulate the Internet Computer, allowing for fast, local execution of canister calls without needing a live network.
- **Instrumentation**: Canister Wasm is automatically instrumented with AFL-style coverage hooks. This allows the fuzzer to see which parts of the code are executed by an input and guide its mutations to explore new code paths.
- **Orchestration**: A simple trait-based system allows you to define the complete fuzzing harness, including canister setup and the logic for each test case.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Rust**: Install via `rustup`.
  ```sh
  rustup default stable
  rustup target add wasm32-unknown-unknown
  ```
- **DFINITY Canister SDK (`dfx`)**: Required for building Motoko canisters. Installation [guide](https://internetcomputer.org/docs/building-apps/getting-started/install).
- **Mops**: A package manager for Motoko.
  ```sh
  npm install -g mops
  ```

## Getting Started

The framework includes several examples in the `examples/` directory. To run the `stable_memory_ops` fuzzer:

1.  **Build and Run the Fuzzer:**
    ```sh
    cargo run --release -p stable_memory_ops
    ```
    This command compiles the `stable_memory_ops` example and its associated canisters, instruments the target canister, and starts the fuzzing loop.

2.  **Observe the Output:**
    You will see `libafl`'s status screen, showing statistics like executions per second, total executions, and coverage.

3.  **Check the Artifacts:**
    Interesting inputs and crashes are saved in the `target/artifacts/` directory.
    - **Corpus**: `target/artifacts/examples/stable_memory_ops/<timestamp>/input/` contains inputs that discovered new code coverage.
    - **Crashes**: `target/artifacts/examples/stable_memory_ops/<timestamp>/crashes/` contains inputs that caused a panic or returned an `ExitKind::Crash`.

## How It Works

The framework is composed of a few key modules:

- **`fuzzer.rs`**: Defines `FuzzerState`, which holds the `PocketIc` instance and information about all canisters under test.
- **`orchestrator.rs`**: Defines the `FuzzerOrchestrator` trait. You implement this trait to create a fuzzing harness. The `run()` method handles the entire `libafl` setup and execution loop.
- **`instrumentation.rs`**: Contains the logic to parse a Wasm file and inject coverage-tracking instrumentation. The `instrument_wasm_for_fuzzing` function is called during the `init` phase of your fuzzer.
- **`util.rs`**: Provides helper functions, such as `read_canister_bytes` to load Wasm from paths specified by environment variables.
  Wasm from a path, which can be specified directly or via an environment variable.

## Creating a New Fuzzer

Follow these steps to create a new fuzzer for your canisters.

### 1. Set Up the Crate and Canisters

1.  **Create a Crate**: Add a new binary crate in the `examples/` directory (e.g., `my_fuzzer`).
2.  **Add Canisters**: Place your canister source code (Rust or Motoko) in the `canisters/` directory.
3.  **Create `build.rs`**: In your new example crate, create a `build.rs` file to compile your canisters. This uses the `build_canister` helper.

    ```rust
    // examples/my_fuzzer/build.rs
    use build_canister::{Canister, CanisterBuildOpts, build_canisters};

    fn main() {
        build_canisters(vec![
            // A Rust canister to be instrumented for coverage
            CanisterBuildOpts {
                name: "my_target_canister",
                ty: Canister::Rust,
                env_var: "MY_TARGET_CANISTER_WASM_PATH",
            },
            // A support canister (e.g., a ledger)
            CanisterBuildOpts {
                name: "support_canister",
                ty: Canister::Rust, // or Canister::Motoko
                env_var: "SUPPORT_CANISTER_WASM_PATH",
            },
        ]);
    }
    ```

### 2. Implement the Fuzzer

In your example's `main.rs`, implement the `FuzzerOrchestrator` trait.

```rust
// examples/my_fuzzer/src/main.rs
use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canister_fuzzer::util::{read_canister_bytes, parse_canister_result_for_trap};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::libafl::executors::ExitKind;
use canister_fuzzer::libafl::inputs::BytesInput;
use pocket_ic::{PocketIcBuilder, PocketIc};
use candid::Principal;

// 1. Define a struct to hold the FuzzerState
struct MyFuzzer(FuzzerState);

// 2. Implement FuzzerStateProvider
impl FuzzerStateProvider for MyFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState { &self.0 }
}

// 3. Implement the main fuzzing logic
impl FuzzerOrchestrator for MyFuzzer {
    fn init(&mut self) {
        // Initialize PocketIc
        let pic = PocketIcBuilder::new().with_application_subnet().build();
        self.0.init_state(pic);
        let pic = self.get_state_machine();

        // Install canisters
        for info in self.0.get_iter_mut_canister_info() {
            let canister_id = pic.create_canister();
            pic.add_cycles(canister_id, 2_000_000_000_000);

            let wasm_bytes = read_canister_bytes(info.wasm_path.clone());
            let module = if info.ty == CanisterType::Coverage {
                // Instrument the target canister
                instrument_wasm_for_fuzzing(&wasm_bytes)
            } else {
                wasm_bytes
            };
            pic.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    fn execute(&self, input: BytesInput) -> ExitKind {
        let pic = self.get_state_machine();
        let target_canister = self.get_coverage_canister_id();
        let payload: Vec<u8> = input.into();

        // Make a canister call with the fuzzer-generated payload
        let result = pic.update_call(
            target_canister,
            Principal::anonymous(),
            "my_canister_method",
            payload,
        );

        // Check for traps
        let (exit_kind, _reply) = parse_canister_result_for_trap(result);
        if exit_kind == ExitKind::Crash {
            return ExitKind::Crash;
        }

        // Add custom logic to check for other bugs (e.g., incorrect state)
        // if is_bug_detected() {
        //     return ExitKind::Crash;
        // }

        ExitKind::Ok
    }
}

// 4. The main function to set up and run the fuzzer
fn main() {
    let mut fuzzer = MyFuzzer(FuzzerState::new(
        vec![
            CanisterInfo {
                id: None,
                name: "my_target_canister".to_string(),
                wasm_path: WasmPath::EnvVar("MY_TARGET_CANISTER_WASM_PATH".to_string()),
                ty: CanisterType::Coverage,
            },
            // Add other canisters here if needed
        ],
        "examples/my_fuzzer".to_string(),
    ));

    fuzzer.run();
}
```

## Reproducing a Crash

When the fuzzer finds a crash, it saves the input that caused it to the `crashes` directory. You can use the `test_one_input` method to debug a specific input without running the full fuzzing loop.

1.  **Locate the Crashing Input**: Find an input file in a path like `target/artifacts/examples/my_fuzzer/<timestamp>/crashes/<input_hash>`.

2.  **Modify `main.rs`**: In your fuzzer's `main` function, comment out the call to `run()` and add a call to `test_one_input()`.

    ```rust
    // examples/my_fuzzer/src/main.rs
    use std::fs;

    // ... (other fuzzer code from the "Creating a New Fuzzer" section)

    fn main() {
        let mut fuzzer = MyFuzzer(FuzzerState::new(
            // ... fuzzer state setup as before
        ));

        // To run the fuzzer:
        // fuzzer.run();

        // To reproduce and debug a specific crash:
        // 1. Update the path to your crash file.
        let crash_input_path = "target/artifacts/examples/my_fuzzer/20240101_120000/crashes/some_input_hash";
        let crash_input = fs::read(crash_input_path).expect("Could not read crash file");

        // 2. Call test_one_input with the crash data.
        fuzzer.test_one_input(crash_input);
    }
    ```

3.  **Run with a Debugger**: Compile and run your fuzzer. The output will show the `ExitKind` from the execution.

## License

This project is licensed under the Apache-2.0 License.