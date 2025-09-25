use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "decode_candid",
        ty: Canister::Rust,
        env_var: "DECODE_CANDID_WASM_PATH",
    }]);
}
