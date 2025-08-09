use ic_state_machine_tests::ErrorCode;
use ic_state_machine_tests::StateMachineBuilder;
use ic_types::{ingress::WasmResult, Cycles};
use libafl::executors::ExitKind;
use libafl::inputs::ValueInput;
use std::path::PathBuf;
use std::time::Duration;

use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, FuzzerState};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{self, FuzzerOrchestrator};
use canister_fuzzer::sandbox_shim::sandbox_main;
use canister_fuzzer::util::read_canister_bytes;

static mut COVERAGE_MAP: &mut [u8] = &mut [0; 65536];

fn main() {
    let fuzzer_state = StableMemoryFuzzer(FuzzerState {
        state: None,
        canisters: vec![CanisterInfo {
            id: None,
            name: "stable_memory".to_string(),
            env_var: "STABLE_MEMORY_WASM_PATH".to_string(),
        }],
        fuzzer_dir: PathBuf::from("examples/stable_memory_ops"),
    });

    sandbox_main(orchestrator::run, fuzzer_state);
}

struct StableMemoryFuzzer(FuzzerState);

impl FuzzerOrchestrator for StableMemoryFuzzer {
    fn init(&mut self) {
        let test = StateMachineBuilder::new()
            .with_log_level(Some(Level::Critical))
            .build();

        let fuzzer_state = &mut self.0;
        fuzzer_state.state = Some(test);

        for info in fuzzer_state.canisters.iter_mut() {
            let module = instrument_wasm_for_fuzzing(&read_canister_bytes(&info.env_var));
            let canister_id = fuzzer_state
                .state
                .as_ref()
                .unwrap()
                .install_canister_with_cycles(module, vec![], None, Cycles::new(5_000_000_000_000))
                .unwrap();
            info.id = Some(canister_id);
        }
    }

    fn setup(&self) {}

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();

        let bytes: Vec<u8> = input.into();
        let result = test.execute_ingress(
            fuzzer_state.get_cansiter_id_by_name("stable_memory"),
            "stable_memory_ops",
            bytes,
        );

        let exit_status = match result {
            Ok(WasmResult::Reject(message)) => {
                // Canister crashing is interesting
                if message.contains("Canister trapped") {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            }
            Err(e) => match e.code() {
                ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => {
                    println!("{e:?} result");
                    ExitKind::Crash
                }
                _ => ExitKind::Ok,
            },
            _ => ExitKind::Ok,
        };

        test.advance_time(Duration::from_secs(1));
        test.tick();

        exit_status
    }

    fn cleanup(&self) {}

    fn input_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("input")
    }

    fn crashes_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("crashes")
    }

    fn corpus_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("corpus")
    }

    #[allow(static_mut_refs)]
    fn set_coverage_map(&self) {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();
        let result = test.query(
            fuzzer_state.get_cansiter_id_by_name("stable_memory"),
            "export_coverage",
            vec![],
        );
        if let Ok(WasmResult::Reply(result)) = result {
            unsafe { COVERAGE_MAP.copy_from_slice(&result) };
        }
    }

    fn get_coverage_map(&self) -> &mut [u8] {
        unsafe { COVERAGE_MAP }
    }
}
