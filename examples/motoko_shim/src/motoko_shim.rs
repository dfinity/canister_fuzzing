use candid::Encode;
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

fn main() {
    let fuzzer_state = MotokoShimFuzzer(FuzzerState {
        state: None,
        canisters: vec![CanisterInfo {
            id: None,
            name: "json_decode".to_string(),
            env_var: "MOTOKO_CANISTER_WASM_PATH".to_string(),
        }],
        fuzzer_dir: "examples/motoko_shim".to_string(),
    });
    sandbox_main(orchestrator::run, fuzzer_state);
}

struct MotokoShimFuzzer(FuzzerState);

impl FuzzerOrchestrator for MotokoShimFuzzer {
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
            fuzzer_state.get_canister_id_by_name("json_decode"),
            "parse_json",
            Encode!(&String::from_utf8_lossy(&bytes)).unwrap(),
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
        self.0.input_dir()
    }

    fn crashes_dir(&self) -> PathBuf {
        self.0.crashes_dir()
    }

    fn corpus_dir(&self) -> PathBuf {
        self.0.corpus_dir()
    }

    #[allow(static_mut_refs)]
    fn set_coverage_map(&self) {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();
        let result = test.query(
            fuzzer_state.get_canister_id_by_name("json_decode"),
            "export_coverage",
            vec![],
        );
        if let Ok(WasmResult::Reply(result)) = result {
            self.0.set_coverage_map(&result);
        }
    }

    fn get_coverage_map(&self) -> &mut [u8] {
        self.0.get_mut_coverage_map()
    }
}
