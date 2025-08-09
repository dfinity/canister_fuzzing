use build_canister::{build_canisters, Canister, CanisterBuildOpts};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "candid_decode",
        ty: Canister::Motoko,
        env_var: "DECODE_CANDID_WASM_PATH",
    }]);
}
