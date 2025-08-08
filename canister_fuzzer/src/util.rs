use std::{fs::File, io::Read};

pub fn read_canister_bytes(env_var: &str) -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var(env_var).unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}
