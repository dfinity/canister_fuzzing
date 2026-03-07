/// Decodes arbitrary bytes as Candid IDL arguments.
///
/// This canister is a fuzzing target — it accepts raw bytes and attempts to decode them
/// using `candid_parser`. Instruction counting is handled automatically by the fuzzing
/// framework's wasm instrumentation (no manual `performance_counter` calls needed).
#[unsafe(export_name = "canister_update decode")]
pub fn decode() {
    let mut decoding_config = candid_parser::DecoderConfig::new();
    decoding_config.set_decoding_quota(2_000_000_000);
    decoding_config.set_skipping_quota(10_000);
    let bytes = ic_cdk::api::msg_arg_data();
    let _b = candid_parser::IDLArgs::from_bytes_with_config(&bytes, &decoding_config);
    ic_cdk::api::msg_reply(vec![]);
}
