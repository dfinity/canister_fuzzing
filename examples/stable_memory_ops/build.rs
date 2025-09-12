use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "stable_memory",
        ty: Canister::Rust,
        env_var: "STABLE_MEMORY_WASM_PATH",
    }]);
}
