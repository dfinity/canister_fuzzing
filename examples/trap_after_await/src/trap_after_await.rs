use std::path::PathBuf;
use std::time::Duration;

use candid::{Decode, Encode, Principal};
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::ValueInput;
use once_cell::sync::OnceCell;
use pocket_ic::PocketIcBuilder;
use slog::Level;

use canfuzz::FuzzerState;
use canfuzz::custom::mutator::candid::CandidTypeDefArgs;
use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder, FuzzerState};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};

use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::read_canister_bytes;

const SYNCHRONOUS_EXECUTION: bool = false;
static SNAPSHOT: OnceCell<(Vec<u8>, Vec<u8>)> = OnceCell::new();

fn main() {
    let ledger = CanisterBuilder::new("ledger")
        .with_wasm_env("LEDGER_WASM_PATH")
        .as_support()
        .build();

    let transfer = CanisterBuilder::new("transfer")
        .with_wasm_env("TRANSFER_WASM_PATH")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("trap_after_await")
        .with_canister(ledger)
        .with_canister(transfer)
        .build();

    let mut fuzzer_state = TrapAfterAwaitFuzzer(state);

    fuzzer_state.run();
}

#[derive(FuzzerState)]
struct TrapAfterAwaitFuzzer(FuzzerState);

impl FuzzerOrchestrator for TrapAfterAwaitFuzzer {
    fn get_candid_args() -> Option<CandidTypeDefArgs> {
        Some(CandidTypeDefArgs {
            definition: PathBuf::from(file!())
                .parent() // src
                .unwrap()
                .parent() // trap_after_await
                .unwrap()
                .parent() // examples
                .unwrap()
                .parent() // canister_fuzzing
                .unwrap()
                .join("canisters/rust/transfer/src/service.did"),
            method: "refund_balance".to_string(),
        })
    }
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

        let ledger_canister_id = test.create_canister();
        test.add_cycles(ledger_canister_id, u128::MAX / 2);
        let module = read_canister_bytes(
            self.as_ref()
                .get_canister_wasm_path_by_name("ledger")
                .clone(),
        );
        test.install_canister(ledger_canister_id, module, vec![], None);

        let main_canister_id = test.create_canister();
        test.add_cycles(main_canister_id, u128::MAX / 2);
        let module = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: read_canister_bytes(
                self.as_ref()
                    .get_canister_wasm_path_by_name("transfer")
                    .clone(),
            ),
            history_size: 8,
            seed: Seed::Random,
        });
        test.install_canister(
            main_canister_id,
            module,
            Encode!(&ledger_canister_id).unwrap(),
            None,
        );

        let canisters = [ledger_canister_id, main_canister_id];
        for (info, id) in self.as_mut().get_iter_mut_canister_info().zip(canisters) {
            info.id = Some(id)
        }

        // Prepare the main canister
        // Adds a local balance of 10_000_000 to anonymous principal
        test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "update_balance",
            Encode!().unwrap(),
        )
        .unwrap();

        // Prepare the ledger canister
        // Adds a ledger balance of 10_000_000 to main_canister_id
        test.update_call(
            ledger_canister_id,
            Principal::anonymous(),
            "setup_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        )
        .unwrap();

        // Assert both balances match
        let b1 = match test.query_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "get_total_balance",
            Encode!().unwrap(),
        ) {
            Ok(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query_call(
            ledger_canister_id,
            Principal::anonymous(),
            "get_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        ) {
            Ok(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // should never fail
        assert_eq!(b1, b2);

        let s1 = test
            .take_canister_snapshot(main_canister_id, None, None)
            .unwrap()
            .id;
        let s2 = test
            .take_canister_snapshot(ledger_canister_id, None, None)
            .unwrap()
            .id;
        SNAPSHOT.set((s1, s2)).unwrap();
    }

    fn setup(&self) {
        let test = self.get_state_machine();
        let main_canister_id = self.get_coverage_canister_id();
        let ledger_canister_id = self.as_ref().get_canister_id_by_name("ledger");
        let (s1, s2) = SNAPSHOT.get().unwrap();
        test.load_canister_snapshot(main_canister_id, None, s1.to_vec())
            .unwrap();
        test.load_canister_snapshot(ledger_canister_id, None, s2.to_vec())
            .unwrap();
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();
        let ledger_canister_id = self.as_ref().get_canister_id_by_name("ledger");

        let trap: Vec<u8> = input.into();
        // Initialize payload from bytes
        // let trap = Encode!(&(bytes_to_u64(input.bytes()) % 500_000)).unwrap();
        // let trap = 3278_u64;

        if SYNCHRONOUS_EXECUTION {
            // Synchronous message execution - ABABAB
            // Each execute_ingress_as is executed in place
            // as a single round
            for _ in 0..3 {
                // Execution result doesn't matter here
                let _result = test.update_call(
                    self.get_coverage_canister_id(),
                    Principal::anonymous(),
                    "refund_balance",
                    trap.clone(),
                );
            }
        } else {
            // Asynchronous setup AABBAB
            // We use submit_ingress and execute_round to trigger
            // asynchronous message execution.
            for i in 0..3 {
                let _messaage_id = test
                    .submit_call(
                        self.get_coverage_canister_id(),
                        Principal::anonymous(),
                        "refund_balance",
                        trap.clone(),
                    )
                    .unwrap();
                if i == 1 {
                    test.tick();
                }
            }
            test.tick();
        }

        // Assert both balances match
        let b1 = match test.query_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "get_total_balance",
            Encode!().unwrap(),
        ) {
            Ok(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query_call(
            ledger_canister_id,
            Principal::anonymous(),
            "get_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        ) {
            Ok(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // can fail
        if b1 != b2 {
            println!("Results fail b1 : {b1}, b2 : {b2}");
            return ExitKind::Crash;
        }
        test.advance_time(Duration::from_secs(60));
        ExitKind::Ok
    }
}
