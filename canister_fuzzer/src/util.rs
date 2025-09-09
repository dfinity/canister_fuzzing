use std::{fs::File, io::Read};

use crate::libafl::executors::ExitKind;
use ic_state_machine_tests::{ErrorCode, UserError, WasmResult};

pub fn read_canister_bytes(env_var: &str) -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var(env_var).unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

pub fn parse_canister_result_for_trap(
    result: Result<WasmResult, UserError>,
) -> (ExitKind, Option<Vec<u8>>) {
    match result {
        Ok(WasmResult::Reply(reply)) => (ExitKind::Ok, Some(reply)),
        Ok(WasmResult::Reject(message)) => {
            // Canister crashing is interesting
            if message.contains("Canister trapped") {
                (ExitKind::Crash, Some(message.into_bytes()))
            } else {
                (ExitKind::Ok, None)
            }
        }
        Err(e) => match e.code() {
            ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => {
                // println!("{e:?}");
                (ExitKind::Crash, None)
            }
            _ => (ExitKind::Ok, None),
        },
    }
}
