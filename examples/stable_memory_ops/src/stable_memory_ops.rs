use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder};
use ic_types::CanisterId;
use ic_types::{ingress::WasmResult, Cycles};
use libafl::executors::ExitKind;
use libafl::inputs::ValueInput;
use std::sync::Arc;
use std::time::Duration;

use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{self, FuzzerOrchestrator};
use canister_fuzzer::sandbox_shim::sandbox_main;
use canister_fuzzer::util::read_canister_bytes;

fn main() {
    let fuzzer_state = StableMemoryFuzzer(FuzzerState::new(
        vec![CanisterInfo {
            id: None,
            name: "stable_memory".to_string(),
            env_var: "STABLE_MEMORY_WASM_PATH".to_string(),
            ty: CanisterType::Coverage,
        }],
        "examples/stable_memory_ops".to_string(),
    ));

    sandbox_main(orchestrator::run, fuzzer_state);
}

struct StableMemoryFuzzer(FuzzerState);

impl FuzzerOrchestrator for StableMemoryFuzzer {
    fn get_fuzzer_dir(&self) -> String {
        self.0.get_fuzzer_dir().clone()
    }

    fn get_state_machine(&self) -> Arc<StateMachine> {
        self.0.get_state_machine()
    }

    fn get_coverage_canister_id(&self) -> CanisterId {
        self.0.get_coverage_canister_id()
    }

    fn init(&mut self) {
        let test = StateMachineBuilder::new()
            .with_log_level(Some(Level::Critical))
            .build();

        self.0.init_state(test);
        let test = self.get_state_machine();

        for info in self.0.get_iter_mut_canister_info() {
            let module = instrument_wasm_for_fuzzing(&read_canister_bytes(&info.env_var));
            let canister_id = test
                .install_canister_with_cycles(module, vec![], None, Cycles::new(5_000_000_000_000))
                .unwrap();
            info.id = Some(canister_id);
        }
    }

    fn setup(&self) {}

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let result =
            test.execute_ingress(self.get_coverage_canister_id(), "stable_memory_ops", bytes);

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
                    println!("{e:?}");
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
}
