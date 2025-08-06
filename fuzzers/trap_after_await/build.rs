use build_canister::{build_canisters, CanisterBuildOpts};

fn main() {
    build_canisters(vec![
        CanisterBuildOpts {
            name: "ledger",
            env_var: "LEDGER_WASM_PATH",
        },
        CanisterBuildOpts {
            name: "transfer",
            env_var: "TRANSFER_WASM_PATH",
        },
    ]);
}
