use build_canister::{build_canisters, Canister, CanisterBuildOpts};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "stable_memory",
        ty: Canister::Rust,
        env_var: "STABLE_MEMORY_WASM_PATH",
    }]);
}
