use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "rusqlite_db",
        ty: Canister::RustWasi,
        env_var: "RUSQLITE_DB_WASM_PATH",
    }]);
}
