use build_canister::{Canister, CanisterBuildOpts, build_canisters};
use candid_parser::bindings::rust::{Config, emit_bindgen};
use candid_parser::configs::Configs;
use candid_parser::typing::pretty_check_file;
use std::path::Path;

fn main() {
    build_canisters(vec![CanisterBuildOpts {
        name: "rusqlite_db",
        ty: Canister::RustWasi,
        env_var: "RUSQLITE_DB_WASM_PATH",
    }]);

    // Generate Rust type bindings from the canister's .did file
    let did_path = Path::new("../../canisters/rust/rusqlite_db/src/service.did");
    let (env, actor, prog) = pretty_check_file(did_path).expect("failed to parse service.did");

    // Configure: add Serialize derive so types work with candid::Encode!
    let config_toml = "[rust]\n\
        attributes = '#[derive(CandidType, Serialize, Deserialize)]'\n";
    let configs: Configs = config_toml.parse().expect("failed to parse config");
    let config = Config::new(configs);

    let (output, _warnings) = emit_bindgen(&config, &env, &actor, &prog);

    let code = format!(
        "// Auto-generated from service.did — do not edit manually.\n\
         use candid::{{self, CandidType, Deserialize}};\n\
         use serde::Serialize;\n\n\
         {}\n",
        output.type_defs,
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("rusqlite_db_types.rs");
    std::fs::write(&out_path, code).expect("failed to write generated types");

    println!("cargo::rerun-if-changed={}", did_path.display());
}
