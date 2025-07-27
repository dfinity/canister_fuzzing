use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_state_machine_tests::two_subnets_simple;
use ic_types::ingress::WasmResult;
use ic_types::Cycles;
use sandbox_shim::sandbox_main;
use std::fs::File;
use std::io::Read;

const SYNCHRONOUS_EXECUTION: bool = false;

fn main() {
    sandbox_main(run);
}

#[allow(dead_code)]
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for &byte in bytes.iter().take(8).rev() {
        result = (result << 8) | byte as u64;
    }
    result
}

fn read_transfer_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("TRANSFER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn read_ledger_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("LEDGER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn run() {
    let (test, _s2) = two_subnets_simple();
    // Install ledger canister
    let ledger_canister_id = test
        .install_canister_with_cycles(
            read_ledger_canister_bytes(),
            vec![],
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    // Install main canister
    let main_canister_id = test
        .install_canister_with_cycles(
            read_transfer_canister_bytes(),
            Encode!(&ledger_canister_id).unwrap(),
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    // Prepare the main canister
    // Adds a local balance of 10_000_000 to anonymous principal
    test.execute_ingress(main_canister_id, "update_balance", Encode!().unwrap())
        .unwrap();

    // Prepare the ledger canister
    // Adds a ledger balance of 10_000_000 to main_canister_id
    test.execute_ingress(
        ledger_canister_id,
        "setup_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    )
    .unwrap();

    // Assert both balances match
    let b1 = match test
        .query(main_canister_id, "get_total_balance", Encode!().unwrap())
        .unwrap()
    {
        WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    let b2 = match test.query(
        ledger_canister_id,
        "get_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    ) {
        Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    // should never fail
    assert_eq!(b1, b2);

    // let bytes = include_bytes!("/ic/rs/canister_fuzzing/trap_after_await/crashes/b9a09e1886048420");
    // let trap = Encode!(&(bytes_to_u64(bytes) % 500_000)).unwrap();
    // println!("Trap {trap:?}");

    // let trap = 3278_u64;
    let trap = Encode!(&(32_u64)).unwrap();

    if SYNCHRONOUS_EXECUTION {
        // Synchronous message execution - ABABAB
        // Each execute_ingress_as is executed in place
        // as a single round
        for _ in 0..3 {
            // Execution result doesn't matter here
            let _result = test.execute_ingress_as(
                PrincipalId::new_anonymous(),
                main_canister_id,
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
                    main_canister_id,
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
        .query(main_canister_id, "get_total_balance", Encode!().unwrap())
        .unwrap()
    {
        WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    let b2 = match test.query(
        ledger_canister_id,
        "get_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    ) {
        Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    // can fail
    if b1 != b2 {
        println!("Results fail b1 : {b1}, b2 : {b2}");
        panic!("Ledger balance doesn't match");
    }
}
