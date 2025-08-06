use build_canister::{build_canisters, CanisterBuildOpts};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "stable_memory",
        env_var: "STABLE_MEMORY_WASM_PATH",
    }]);
}
