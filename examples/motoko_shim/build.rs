use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "json_decode",
        ty: Canister::Motoko,
        env_var: "MOTOKO_CANISTER_WASM_PATH",
    }]);
}
