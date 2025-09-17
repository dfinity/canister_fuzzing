use pocket_ic::{ErrorCode, RejectResponse};
use std::{fs::File, io::Read};

use crate::{fuzzer::WasmPath, libafl::executors::ExitKind};

pub fn read_canister_bytes(wasm_path: WasmPath) -> Vec<u8> {
    let wasm_path = match wasm_path {
        WasmPath::EnvVar(env_var) => std::path::PathBuf::from(std::env::var(env_var).unwrap()),
        WasmPath::Path(path) => path,
    };
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

pub fn parse_canister_result_for_trap(
    result: Result<Vec<u8>, RejectResponse>,
) -> (ExitKind, Option<Vec<u8>>) {
    match result {
        Ok(reply) => (ExitKind::Ok, Some(reply)),
        Err(e) => match e.error_code {
            ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => {
                // println!("{e:?}");
                (ExitKind::Crash, None)
            }
            _ => (ExitKind::Ok, None),
        },
    }
}
