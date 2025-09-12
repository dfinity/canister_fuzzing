use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "candid_decode",
        ty: Canister::Motoko,
        env_var: "DECODE_CANDID_WASM_PATH",
    }]);
}
