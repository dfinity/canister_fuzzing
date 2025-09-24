# Canister Fuzzing Framework

A coverage-guided fuzzer for Internet Computer canisters, built on `libafl` and `pocket-ic`. It finds bugs by instrumenting canister Wasm, emulating the IC with `pocket-ic`, and using `libafl` to explore code paths.

## Building a new fuzzer

To build a fuzzer, one must implement the `FuzzerOrchestrator` trait. This involves two main parts: an `init` function to set up the canisters and an `execute` function that runs for each input.

```rust
// my_fuzzer/src/main.rs
use canfuzz::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canfuzz::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canfuzz::util::parse_canister_result_for_trap;
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::BytesInput;
use candid::Principal;

// 1. Define a struct for the fuzzer state
struct MyFuzzer(FuzzerState);

// 2. Implement the trait to provide access to the state
impl FuzzerStateProvider for MyFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState { &self.0 }
}

// 3. Implement the core fuzzing logic
impl FuzzerOrchestrator for MyFuzzer {
    /// Sets up the IC environment and installs canisters.
    fn init(&mut self) {
        self.default_init(); // A helper that initializes PocketIc and installs canisters
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
    let canisters = vec![
        CanisterInfo {
            name: "my_target_canister".to_string(),
            ty: CanisterType::Coverage,
            // Specify the path to your pre-compiled Wasm.
            // For complex builds, you can use a build.rs and WasmPath::EnvVar.
            wasm_path: WasmPath::Path("path/to/your/canister.wasm".to_string()),
            id: None,
        },
        // Add any other supporting canisters here.
    ];

    let mut fuzzer = MyFuzzer(FuzzerState::new("my_fuzzer", canisters));
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
        let mut fuzzer = MyFuzzer(FuzzerState::new("my_fuzzer", canisters));

        // fuzzer.run(); // Comment out the main fuzzing loop

        // Use test_one_input to reproduce a specific crash
        let crash_input = fs::read("path/to/your/crash/file").unwrap();
        fuzzer.test_one_input(crash_input);
    }
    ```

## How It Works

The canister fuzzing framework integrates two main components:

*   **`libafl` (Fuzzing Engine)**: At its core, the framework uses `libafl`, a state-of-the-art fuzzing library. `libafl` is responsible for the main fuzzing loop, which includes:
    *   Generating and mutating inputs.
    *   Executing test cases with the generated inputs.
    *   Collecting code coverage feedback to guide future mutations.
    *   Managing the corpus of interesting inputs and reporting crashes.

*   **Wasm Instrumentation**: To enable coverage-guided fuzzing, the target canister's Wasm module is automatically instrumented before being deployed. This process modifies the Wasm to provide execution feedback to `libafl`.
    *   **Instrumentation Pass**: The framework uses a Wasm-to-Wasm transformation pass. This pass analyzes the canister's code and injects small snippets of code at various points (typically at every basic block or edge).
    *   **Coverage Map**: A global array, known as the "coverage map" or "edges map," is added to the Wasm module's memory. This map is shared between the instrumented code and the fuzzer's feedback mechanism. Each entry in the map corresponds to a specific code block or branch in the original program.
    *   **Tracking Execution**: The injected code snippets are simple: they update the coverage map whenever they are executed. For example, a hit counter for a specific code block is incremented. This allows the fuzzer to know which parts of the canister were executed for a given input.
    *   **Exporting Coverage Data**: Since the canister runs in the sandboxed `pocket-ic` environment, a special query method (e.g., `__get_coverage`) is added to the Wasm module. After each test case, the fuzzer calls this method to retrieve the coverage map from the canister's memory. This data is then passed to `libafl` to guide the next round of mutations.

## License

This project is licensed under the Apache-2.0 License.