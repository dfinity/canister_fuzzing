use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
pub enum Canister {
    Rust,
    Motoko,
}

#[derive(Debug)]
pub struct CanisterBuildOpts<'a> {
    pub name: &'a str,
    pub ty: Canister,
    pub env_var: &'a str,
}

pub fn build_canisters(canisters: Vec<CanisterBuildOpts>) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FORCE_BUILD");

    for canister in canisters {
        let wasm_path = match canister.ty {
            Canister::Rust => build_canister(canister.name),
            Canister::Motoko => build_motoko_canister(canister.name),
        };

        println!(
            "cargo:rustc-env={}={}",
            canister.env_var,
            wasm_path.display()
        );
    }
}

/// A helper function to build a given canister.
fn build_canister(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let canister_path = workspace_root.join("canisters").join("rust").join(name);

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

    get_build_dir().join(format!("{name}.wasm"))
}

fn get_build_dir() -> PathBuf {
    get_target_dir().join("wasm32-unknown-unknown/release")
}

fn get_target_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    workspace_root.join("target/canister_build")
}

fn build_motoko_canister(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let canister_root_path = workspace_root.join("canisters").join("motoko");

    println!(
        "cargo:rerun-if-changed={}/mops.toml",
        canister_root_path.display()
    );

    println!(
        "cargo:rerun-if-changed={}/main.mo",
        canister_root_path.join("src").join(name).display()
    );

    assert!(std::env::set_current_dir(canister_root_path.clone()).is_ok());

    let status = Command::new("dfx")
        .arg("build")
        .arg(name)
        .arg("--check")
        .status()
        .unwrap_or_else(|_| panic!("Failed to execute cargo build for canister '{name}'"));

    if !status.success() {
        panic!("Failed to build canister '{name}'. Exit status: {status}");
    }

    PathBuf::from(format!(
        "{}/.dfx/local/canisters/{name}/{name}.wasm",
        canister_root_path.display()
    ))
}
