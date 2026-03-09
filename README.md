# Canister Fuzzing Framework

A coverage-guided fuzzer for Internet Computer canisters, built on `libafl` and `pocket-ic`. It finds bugs by instrumenting canister Wasm, emulating the IC with `pocket-ic`, and using `libafl` to explore code paths.

## Building a new fuzzer

To build a fuzzer, one must implement the `FuzzerOrchestrator` trait. This involves two main parts: an `init` function to set up the canisters and an `execute` function that runs for each input.

```rust
// my_fuzzer/src/main.rs
use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder, FuzzerState, WasmPath};
use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::parse_canister_result_for_trap;
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::BytesInput;
use candid::Principal;

// 1. Define a struct for the fuzzer state using the macro
canfuzz::define_fuzzer_state!(MyFuzzer);

// 2. Implement the core fuzzing logic
impl FuzzerOrchestrator for MyFuzzer {
    /// Sets up the IC environment and installs canisters.
    fn init(&mut self) {
        // A helper that automatically initializes PocketIc and installs canisters.
        // Canisters are expected to be instrumented here.
        self.as_mut().setup_canisters();
    }

    /// Executes one test case with a given input.
    fn execute(&self, input: BytesInput) -> ExitKind {
        let payload: Vec<u8> = input.into();
        let target_canister = self.get_coverage_canister_id();
        let pic = self.get_state_machine();

        // Call a method on the target canister
        let result = pic.update_call(
            target_canister,
            Principal::anonymous(),
            "my_canister_method",
            payload,
        );

        // Check for traps (panics). This is a common crash condition.
        parse_canister_result_for_trap(result)

        // For other bugs, add custom checks and return ExitKind::Crash if found.
        // if is_bug_detected() { return ExitKind::Crash; }
        // ExitKind::Ok
    }
}

// 4. The main function to configure and run the fuzzer
fn main() {
    // Define the canisters for the test environment.
    // The `Coverage` canister will be instrumented automatically.
    
    // For complex builds, you can use a build.rs and .with_wasm_env()
    let target = CanisterBuilder::new("my_target_canister")
        .with_wasm_path("path/to/your/canister.wasm")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("my_fuzzer")
        .with_canister(target)
        // .with_canister(other_canister)
        .build();

    let mut fuzzer = MyFuzzer(state);
    fuzzer.run();
}
```

## Running an example

### Prerequisites

1.  **Rust**:
    ```sh
    rustup default stable
    rustup target add wasm32-unknown-unknown
    ```
2.  **DFX**: [Installation guide](https://internetcomputer.org/docs/current/developer-docs/getting-started/install/index.html) (for Motoko canisters).
3.  **Mops**: `npm install -g mops` (for Motoko canisters).


The `examples/` directory contains sample fuzzers. To run the `stable_memory_ops` example:

1.  **Build and Run:**
    ```sh
    cargo run --release -p stable_memory_ops
    ```

2.  **Check Output:**
    The fuzzer will start and display a status screen. Results, including new inputs (`corpus`) and crashes, are saved to a timestamped directory inside `artifacts/`. The exact path is printed at startup.

## Reproduce a Crash

When a crash is found, the input is saved to the `artifacts/.../crashes/` directory. Use the `test_one_input` method to reproduce it for debugging.

1.  **Find the Crash File:** Copy the path to a crash input file from the fuzzer's output directory.

2.  **Modify `main` to Test One Input:**
    ```rust
    use std::fs;

    fn main() {
        // ... (fuzzer and canister setup from above)
        let mut fuzzer = MyFuzzer(state);

        // fuzzer.run(); // Comment out the main fuzzing loop

        // Use test_one_input to reproduce a specific crash
        let crash_input = fs::read("path/to/your/crash/file").unwrap();
        fuzzer.test_one_input(crash_input);
    }
    ```

## How It Works

The framework connects three components:

1. **`pocket-ic` (IC Emulator)** — Runs canisters locally in-process. The fuzzer installs instrumented Wasm into `pocket-ic` and makes canister calls for each test input.

2. **Wasm Instrumentation** — Before deployment, the target canister's Wasm module is transformed to provide execution feedback:

   * **Branch coverage**: An AFL-style instrumentation pass injects code at every basic block and branch. Each instrumentation point updates a shared coverage map using XOR-based edge hashing with a configurable history size.

   * **Coverage export**: A special method (`__export_coverage_for_afl`) is added to the Wasm module so the fuzzer can retrieve the coverage map after each execution.

   * **Instruction count maximization** *(optional)*: When `instrument_instruction_count: true` is set, wrapper functions are injected around each `canister_update` export. The wrappers read `ic0.performance_counter` after the original method returns and subtract the estimated AFL instrumentation overhead. A separate export (`__export_instruction_count_for_afl`) lets the fuzzer retrieve the count. Combined with `instruction_config()` returning `InstructionConfig { enabled: true, .. }` in `FuzzerOrchestrator`, this guides the fuzzer toward inputs that consume the most IC instructions — no changes to the target canister's source code required. See the `decode_candid_by_instructions` example.

3. **`libafl` (Fuzzing Engine)** — Drives the main loop: generating inputs, executing them via `pocket-ic`, collecting coverage (and optionally instruction count) feedback, and managing the corpus. The framework also includes a **Candid-aware mutator** that can parse `.did` files and perform structure-aware mutations on Candid-encoded inputs.

## License

This project is licensed under the Apache-2.0 License.