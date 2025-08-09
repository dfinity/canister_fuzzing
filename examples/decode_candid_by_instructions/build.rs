use build_canister::{build_canisters, Canister, CanisterBuildOpts};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "decode_candid",
        ty: Canister::Rust,
        env_var: "DECODE_CANDID_WASM_PATH",
    }]);
}
