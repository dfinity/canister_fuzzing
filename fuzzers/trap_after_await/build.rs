// fuzzers/trap_after_await/build.rs

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // --- Step 1: Define Canister Names ---
    let canisters_to_build = ["ledger", "transfer"];

    // --- Step 2: Build Canisters as Wasm ---
    println!("cargo:rerun-if-changed=build.rs");
    for canister_name in canisters_to_build {
        build_canister(canister_name);
    }

    // Set env var for the ledger canister
    let ledger_wasm_path = get_build_dir().join("ledger_instrumented.wasm");
    println!(
        "cargo:rustc-env=LEDGER_WASM_PATH={}",
        ledger_wasm_path.display()
    );

    // Set env var for the transfer canister
    let transfer_wasm_path = get_build_dir().join("transfer_instrumented.wasm");
    println!(
        "cargo:rustc-env=TRANSFER_WASM_PATH={}",
        transfer_wasm_path.display()
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
    println!(
        "cargo:rerun-if-changed={}/instrumentation/src/main.rs",
        workspace_root.display()
    );

    println!(
        "cargo:rerun-if-changed={}/instrumentation/Cargo.toml",
        workspace_root.display()
    );

    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo_bin.clone())
        .arg("build")
        .arg("--package")
        .arg(name)
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--release")
        .arg("--target-dir")
        .arg(get_target_dir().display().to_string())
        .status()
        .unwrap_or_else(|_| panic!("Failed to execute cargo build for canister '{name}'"));

    if !status.success() {
        panic!("Failed to build canister '{name}'. Exit status: {status}");
    }

    let wasm_path = get_build_dir().join(format!("{name}.wasm"));
    let wasm_instrumented_path = get_build_dir().join(format!("{name}_instrumented.wasm"));

    let status = Command::new(cargo_bin)
        .arg("run")
        .arg("--package")
        .arg("instrumentation")
        .arg("--bin")
        .arg("instrumentation")
        .arg("--release")
        .arg("--target-dir")
        .arg(get_target_dir().display().to_string())
        .arg(wasm_path.display().to_string())
        .arg(wasm_instrumented_path.display().to_string())
        .status()
        .unwrap_or_else(|_| panic!("Failed to execute cargo build for canister '{name}'"));

    if !status.success() {
        panic!("Failed to build canister '{name}'. Exit status: {status}");
    }
}

fn get_build_dir() -> PathBuf {
    get_target_dir().join("wasm32-unknown-unknown/release")
}

fn get_target_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    workspace_root.join("target/canister_build")
}