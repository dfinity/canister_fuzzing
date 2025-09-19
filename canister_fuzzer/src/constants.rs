//! This module defines constants used throughout the canister fuzzer framework.
//! These constants are related to AFL-style instrumentation, IC System API,
//! and the communication between the fuzzer and the instrumented canister.

/// The size of the shared memory map used for AFL-style coverage tracking.
/// This value (2^16) is standard for AFL.
/// The actual memory map size is AFL_COVERAGE_MAP_SIZE * history_size
pub const AFL_COVERAGE_MAP_SIZE: i32 = 65536;

/// The module name for the IC System API.
/// Wasm modules import functions from "ic0" to interact with the IC.
pub const API_VERSION_IC0: &str = "ic0";

/// The name of the function exported by an instrumented canister to expose its coverage map.
/// The fuzzer orchestrator calls this function to retrieve coverage data.
pub const COVERAGE_FN_EXPORT_NAME: &str = "__export_coverage_for_afl";
