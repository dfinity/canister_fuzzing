use candid::Principal;
use canfuzz::custom::mutator::candid::CandidTypeDefArgs;
use canfuzz::define_fuzzer_state;
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::BytesInput;
use once_cell::sync::OnceCell;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;

use slog::Level;

use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};
use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::{parse_canister_result_for_trap, read_canister_bytes};

static SNAPSHOT_ID: OnceCell<Vec<u8>> = OnceCell::new();
define_fuzzer_state!(RusqliteFuzzer);

fn main() {
    let canister = CanisterBuilder::new("rusqlite_db")
        .with_wasm_env("RUSQLITE_DB_WASM_PATH")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("rusqlite_fuzz")
        .with_canister(canister)
        .build();

    let mut fuzzer = RusqliteFuzzer(state);
    fuzzer.run();
}

impl FuzzerOrchestrator for RusqliteFuzzer {
    fn get_candid_args() -> Option<CandidTypeDefArgs> {
        Some(CandidTypeDefArgs {
            definition: PathBuf::from(file!())
                .parent() // src
                .unwrap()
                .parent() // rusqlite_fuzz
                .unwrap()
                .parent() // examples
                .unwrap()
                .parent() // canister_fuzzing
                .unwrap()
                .join("canisters/rust/rusqlite_db/src/service.did"),
            method: "sql_ops".to_string(),
        })
    }

    fn corpus_dir(&self) -> PathBuf {
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
            .with_auto_progress()
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
                instrument_instruction_count: true,
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

    fn execute(&self, input: BytesInput) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let result = test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "sql_ops",
            bytes,
        );

        parse_canister_result_for_trap(result)
    }

    fn instruction_config() -> canfuzz::orchestrator::InstructionConfig {
        canfuzz::orchestrator::InstructionConfig {
            enabled: true,
            max_instruction_count: Some(4_000_000_000),
        }
    }
}
