// fuzzers/decode_candid_by_instructions/build.rs

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // --- Step 1: Define Canister Name ---
    let canister_to_build = "decode_candid";

    // --- Step 2: Build Canister as Wasm ---
    println!("cargo:rerun-if-changed=build.rs");
    build_canister(canister_to_build);

    // --- Step 3: Set Environment Variable ---
    // The build script's current directory is the crate's root (e.g., fuzzers/decode_candid_by_instructions)
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Navigate up to the workspace root
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let wasm_target_dir = workspace_root.join("target/wasm32-unknown-unknown/release");

    // Set env var for the decode_candid canister
    let wasm_path = wasm_target_dir.join("decode_candid.wasm");
    println!(
        "cargo:rustc-env=DECODE_CANDID_WASM_PATH={}",
        wasm_path.display()
    );
}

/// A helper function to build a given canister.
fn build_canister(name: &str) {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let canister_path = workspace_root.join("canisters").join(name);

    println!(
        "cargo:rerun-if-changed={}/src/lib.rs",
        canister_path.display()
    );
    println!(
        "cargo:rerun-if-changed={}/src/service.did",
        canister_path.display()
    );
    println!(
        "cargo:rerun-if-changed={}/Cargo.toml",
        canister_path.display()
    );

    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo_bin)
        .arg("build")
        .arg("--package")
        .arg(name)
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--release")
        .status()
        .unwrap_or_else(|_| panic!("Failed to execute cargo build for canister '{}'", name));

    if !status.success() {
        panic!(
            "Failed to build canister '{}'. Exit status: {}",
            name, status
        );
    }
}
