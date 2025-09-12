use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "ecdsa_sign",
        ty: Canister::Motoko,
        env_var: "MOTOKO_CANISTER_WASM_PATH",
    }]);
}
