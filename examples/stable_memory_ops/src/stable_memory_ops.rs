use candid::Principal;
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::ValueInput;
use once_cell::sync::OnceCell;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;
use std::time::Duration;

use slog::Level;

use canfuzz::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};
use canfuzz::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canfuzz::util::{parse_canister_result_for_trap, read_canister_bytes};

static SNAPSHOT_ID: OnceCell<Vec<u8>> = OnceCell::new();

fn main() {
    let mut fuzzer_state = StableMemoryFuzzer(FuzzerState::new(
        "stable_memory_ops",
        vec![CanisterInfo {
            id: None,
            name: "stable_memory".to_string(),
            wasm_path: WasmPath::EnvVar("STABLE_MEMORY_WASM_PATH".to_string()),
            ty: CanisterType::Coverage,
        }],
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
    fn corpus_dir(&self) -> std::path::PathBuf {
        PathBuf::from(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("corpus")
    }

    fn init(&mut self) {
        let test = PocketIcBuilder::new()
            .with_application_subnet()
            .with_log_level(Level::Critical)
            .build();
        self.0.init_state(test);
        let test = self.get_state_machine();

        for info in self.0.get_iter_mut_canister_info() {
            let canister_id = test.create_canister();
            test.add_cycles(canister_id, u128::MAX / 2);
            let module = instrument_wasm_for_fuzzing(InstrumentationArgs {
                wasm_bytes: read_canister_bytes(info.wasm_path.clone()),
                history_size: 8,
                seed: Seed::Random,
            });
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }

        let snapshot = test
            .take_canister_snapshot(self.get_coverage_canister_id(), None, None)
            .unwrap();
        SNAPSHOT_ID.set(snapshot.id).unwrap();
    }

    fn setup(&self) {
        let test = self.get_state_machine();
        test.load_canister_snapshot(
            self.get_coverage_canister_id(),
            None,
            SNAPSHOT_ID.get().unwrap().to_vec(),
        )
        .unwrap();
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
        test.advance_time(Duration::from_secs(60));

        exit_status
    }
}
