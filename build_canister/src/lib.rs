// fuzzers/decode_candid_by_instructions/build.rs

use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
pub struct CanisterBuildOpts<'a> {
    pub name: &'a str,
    pub env_var: &'a str,
}

pub fn build_canisters(canisters: Vec<CanisterBuildOpts>) {
    println!("cargo:rerun-if-changed=build.rs");

    for canister in canisters {
        build_canister(canister.name);
        let wasm_path = get_build_dir().join(format!("{}_instrumented.wasm", canister.name));
        println!(
            "cargo:rustc-env={}={}",
            canister.env_var,
            wasm_path.display()
        );
    }
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
