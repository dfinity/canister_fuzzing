use build_canister::{Canister, CanisterBuildOpts, build_canisters};

fn main() {
    build_canisters(vec![
        CanisterBuildOpts {
            name: "ledger",
            ty: Canister::Rust,
            env_var: "LEDGER_WASM_PATH",
        },
        CanisterBuildOpts {
            name: "transfer",
            ty: Canister::Rust,
            env_var: "TRANSFER_WASM_PATH",
        },
    ]);
}
