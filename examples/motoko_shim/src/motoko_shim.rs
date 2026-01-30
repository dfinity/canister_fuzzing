use candid::{Encode, Principal};
use canfuzz::define_fuzzer_state;
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::ValueInput;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;
use std::time::Duration;

use slog::Level;

use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};
use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::{parse_canister_result_for_trap, read_canister_bytes};

define_fuzzer_state!(MotokoShimFuzzer);

fn main() {
    let canister = CanisterBuilder::new("json_decode")
        .with_wasm_env("MOTOKO_CANISTER_WASM_PATH")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("motoko_shim")
        .with_canister(canister)
        .build();

    let mut fuzzer_state = MotokoShimFuzzer(state);
    fuzzer_state.run();
}

impl FuzzerOrchestrator for MotokoShimFuzzer {
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
        self.as_mut().init_state(test);
        let test = self.get_state_machine();

        for info in self.as_mut().get_iter_mut_canister_info() {
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
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();
        let bytes: Vec<u8> = input.into();
        let result = test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "parse_json",
            Encode!(&String::from_utf8_lossy(&bytes)).unwrap(),
        );

        let exit_status = parse_canister_result_for_trap(result);

        test.advance_time(Duration::from_secs(60));

        exit_status
    }
}
