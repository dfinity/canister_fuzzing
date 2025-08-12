use candid::{Decode, Encode};
use ic_state_machine_tests::{two_subnets_simple, StateMachine};
use ic_types::{ingress::WasmResult, Cycles};
use ic_types::{CanisterId, PrincipalId};
use libafl::executors::ExitKind;
use libafl::inputs::ValueInput;
use std::sync::Arc;

use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{self, FuzzerOrchestrator};
use canister_fuzzer::sandbox_shim::sandbox_main;
use canister_fuzzer::util::read_canister_bytes;

const SYNCHRONOUS_EXECUTION: bool = false;

fn main() {
    let fuzzer_state = TrapAfterAwaitFuzzer(FuzzerState::new(
        vec![
            CanisterInfo {
                id: None,
                name: "ledger".to_string(),
                env_var: "LEDGER_WASM_PATH".to_string(),
                ty: CanisterType::Coverage,
            },
            CanisterInfo {
                id: None,
                name: "transfer".to_string(),
                env_var: "TRANSFER_WASM_PATH".to_string(),
                ty: CanisterType::Support,
            },
        ],
        "examples/trap_after_await".to_string(),
    ));

    sandbox_main(orchestrator::run, fuzzer_state);
}

struct TrapAfterAwaitFuzzer(FuzzerState);

impl FuzzerOrchestrator for TrapAfterAwaitFuzzer {
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
        let (test, _s) = two_subnets_simple();

        // DANGERRR: It's unknwown why the strong ref count is 2 here.
        let stolen_value: StateMachine = unsafe {
            let ptr = Arc::as_ptr(&test) as *mut StateMachine;
            let value = std::ptr::read(ptr);
            std::mem::forget(test);
            value
        };

        self.0.init_state(stolen_value);
        let test = self.get_state_machine();

        let module = instrument_wasm_for_fuzzing(&read_canister_bytes(
            &self.0.get_canister_env_by_name("ledger"),
        ));

        let ledger_canister_id = test
            .install_canister_with_cycles(module, vec![], None, Cycles::new(u128::MAX / 2))
            .unwrap();

        let module = instrument_wasm_for_fuzzing(&read_canister_bytes(
            &self.0.get_canister_env_by_name("transfer"),
        ));

        let main_canister_id = test
            .install_canister_with_cycles(
                module,
                Encode!(&ledger_canister_id).unwrap(),
                None,
                Cycles::new(u128::MAX / 2),
            )
            .unwrap();

        let canisters = [ledger_canister_id, main_canister_id];
        for (info, id) in self.0.get_iter_mut_canister_info().zip(canisters) {
            info.id = Some(id)
        }
    }

    fn setup(&self) {
        let test = self.get_state_machine();
        let ledger_canister_id = self.0.get_canister_id_by_name("ledger");

        // Prepare the main canister
        // Adds a local balance of 10_000_000 to anonymous principal
        test.execute_ingress(
            self.get_coverage_canister_id(),
            "update_balance",
            Encode!().unwrap(),
        )
        .unwrap();

        // Prepare the ledger canister
        // Adds a ledger balance of 10_000_000 to main_canister_id
        test.execute_ingress(
            ledger_canister_id,
            "setup_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        )
        .unwrap();

        // Assert both balances match
        let b1 = match test
            .query(
                self.get_coverage_canister_id(),
                "get_total_balance",
                Encode!().unwrap(),
            )
            .unwrap()
        {
            WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query(
            ledger_canister_id,
            "get_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        ) {
            Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // should never fail
        assert_eq!(b1, b2);
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
                let _result = test.execute_ingress_as(
                    PrincipalId::new_anonymous(),
                    self.get_coverage_canister_id(),
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
                    .submit_ingress_as(
                        PrincipalId::new_anonymous(),
                        self.get_coverage_canister_id(),
                        "refund_balance",
                        trap.clone(),
                    )
                    .unwrap();
                if i == 1 {
                    test.execute_round();
                }
            }
            test.execute_round();
        }

        // Assert both balances match
        let b1 = match test
            .query(
                self.get_coverage_canister_id(),
                "get_total_balance",
                Encode!().unwrap(),
            )
            .unwrap()
        {
            WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query(
            ledger_canister_id,
            "get_balance",
            Encode!(&self.get_coverage_canister_id(), &10_000_000_u64).unwrap(),
        ) {
            Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // can fail
        if b1 != b2 {
            println!("Results fail b1 : {b1}, b2 : {b2}");
            return ExitKind::Crash;
        }
        ExitKind::Ok
    }

    fn cleanup(&self) {}
}
