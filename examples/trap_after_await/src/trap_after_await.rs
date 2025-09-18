use candid::{Decode, Encode, Principal};
use canister_fuzzer::libafl::executors::ExitKind;
use canister_fuzzer::libafl::inputs::ValueInput;
use once_cell::sync::OnceCell;
use pocket_ic::PocketIcBuilder;
use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canister_fuzzer::util::read_canister_bytes;

const SYNCHRONOUS_EXECUTION: bool = false;
static SNAPSHOT: OnceCell<(Vec<u8>, Vec<u8>)> = OnceCell::new();

fn main() {
    let mut fuzzer_state = TrapAfterAwaitFuzzer(FuzzerState::new(
        vec![
            CanisterInfo {
                id: None,
                name: "ledger".to_string(),
                wasm_path: WasmPath::EnvVar("LEDGER_WASM_PATH".to_string()),
                ty: CanisterType::Support,
            },
            CanisterInfo {
                id: None,
                name: "transfer".to_string(),
                wasm_path: WasmPath::EnvVar("TRANSFER_WASM_PATH".to_string()),
                ty: CanisterType::Coverage,
            },
        ],
        Some("examples/trap_after_await".to_string()),
    ));

    fuzzer_state.run();
}

struct TrapAfterAwaitFuzzer(FuzzerState);

impl FuzzerStateProvider for TrapAfterAwaitFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState {
        &self.0
    }
}

impl FuzzerOrchestrator for TrapAfterAwaitFuzzer {
    fn init(&mut self) {
        let test = PocketIcBuilder::new()
            .with_application_subnet()
            .with_log_level(Level::Critical)
            .build();

        self.0.init_state(test);
        let test = self.get_state_machine();

        let ledger_canister_id = test.create_canister();
        test.add_cycles(ledger_canister_id, u128::MAX / 2);
        let module = read_canister_bytes(self.0.get_canister_wasm_path_by_name("ledger").clone());
        test.install_canister(ledger_canister_id, module, vec![], None);

        let main_canister_id = test.create_canister();
        test.add_cycles(main_canister_id, u128::MAX / 2);
        let module = instrument_wasm_for_fuzzing(
            &read_canister_bytes(self.0.get_canister_wasm_path_by_name("transfer").clone()),
            8,
        );
        test.install_canister(
            main_canister_id,
            module,
            Encode!(&ledger_canister_id).unwrap(),
            None,
        );

        let canisters = [ledger_canister_id, main_canister_id];
        for (info, id) in self.0.get_iter_mut_canister_info().zip(canisters) {
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
        let ledger_canister_id = self.0.get_canister_id_by_name("ledger");
        let (s1, s2) = SNAPSHOT.get().unwrap();
        test.load_canister_snapshot(main_canister_id, None, s1.to_vec())
            .unwrap();
        test.load_canister_snapshot(ledger_canister_id, None, s2.to_vec())
            .unwrap();
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();
        let ledger_canister_id = self.0.get_canister_id_by_name("ledger");

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
        ExitKind::Ok
    }
}
