use candid::Principal;
use canister_fuzzer::libafl::executors::ExitKind;
use canister_fuzzer::libafl::inputs::ValueInput;
use pocket_ic::PocketIcBuilder;
use std::time::Duration;

use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canister_fuzzer::util::{parse_canister_result_for_trap, read_canister_bytes};
fn main() {
    let mut fuzzer_state = StableMemoryFuzzer(FuzzerState::new(
        vec![CanisterInfo {
            id: None,
            name: "stable_memory".to_string(),
            wasm_path: WasmPath::EnvVar("STABLE_MEMORY_WASM_PATH".to_string()),
            ty: CanisterType::Coverage,
        }],
        Some("examples/stable_memory_ops".to_string()),
    ));

    fuzzer_state.run();
}

struct StableMemoryFuzzer(FuzzerState);

impl FuzzerStateProvider for StableMemoryFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState {
        &self.0
    }
}

impl FuzzerOrchestrator for StableMemoryFuzzer {
    fn init(&mut self) {
        let test = PocketIcBuilder::new()
            .with_application_subnet()
            .with_log_level(Level::Critical)
            .build();
        self.0.init_state(test);
        let test = self.get_state_machine();

        for info in self.0.get_iter_mut_canister_info() {
            let canister_id = test.create_canister();
            test.add_cycles(canister_id, 5_000_000_000_000);
            let module =
                instrument_wasm_for_fuzzing(&read_canister_bytes(info.wasm_path.clone()), 8);
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let result = test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "stable_memory_ops",
            bytes,
        );

        let exit_status = parse_canister_result_for_trap(result);
        test.advance_time(Duration::from_secs(1));
        test.tick();

        exit_status.0
    }
}
