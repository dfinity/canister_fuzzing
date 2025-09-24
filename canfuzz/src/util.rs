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

pub fn parse_canister_result_for_trap(result: Result<Vec<u8>, RejectResponse>) -> ExitKind {
    match result {
        Ok(_) => ExitKind::Ok,
        Err(e) => {
            // println!("{e:?}");
            match e.error_code {
                ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => ExitKind::Crash,
                ErrorCode::CanisterMemoryAccessLimitExceeded
                | ErrorCode::InsufficientMemoryAllocation
                | ErrorCode::CanisterOutOfMemory
                | ErrorCode::CanisterWasmMemoryLimitExceeded => ExitKind::Oom,
                ErrorCode::CanisterInstructionLimitExceeded => ExitKind::Timeout,
                _ => ExitKind::Ok, // How to handle other errors?
            }
        }
    }
}
