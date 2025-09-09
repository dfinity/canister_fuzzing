//! This module provides functionality to instrument WebAssembly (Wasm) modules
//! for coverage-guided fuzzing, specifically implementing an AFL-style instrumentation.
//!
//! The primary goal is to inject code into a Wasm module that tracks execution paths.
//! This is achieved by:
//! 1.  Injecting global variables to maintain state, such as the previous location.
//! 2.  Adding instrumentation code at the beginning of basic blocks (before branch instructions).
//! 3.  Exporting a function (`export_coverage`) that allows the fuzzer to retrieve the
//!     coverage map from the canister.

use anyhow::Result;
use rand::Rng;
use wirm::ir::function::FunctionBuilder;
use wirm::ir::id::{FunctionID, GlobalID};
use wirm::ir::module::module_functions::FuncKind;
use wirm::ir::types::{InitExpr, Instructions, Value};
use wirm::wasmparser::{MemArg, Operator, Validator};
use wirm::{DataType, InitInstr, Module, Opcode};

use crate::constants::{AFL_COVERAGE_MAP_SIZE, API_VERSION_IC0, COVERAGE_FN_EXPORT_NAME};

/// Instruments the given Wasm bytes for fuzzing.
///
/// This function takes a raw Wasm module, applies AFL-style instrumentation for
/// coverage tracking, and returns the instrumented Wasm module as a vector of bytes.
/// The resulting Wasm is validated before being returned.
pub fn instrument_wasm_for_fuzzing(wasm_bytes: &[u8]) -> Vec<u8> {
    let mut module =
        Module::parse(wasm_bytes, false).expect("Failed to parse module with ic-wasm-transform");

    instrument_for_afl(&mut module).expect("Unable to instrument wasm module for AFL");

    let instrumented_wasm = module.encode();

    validate_wasm(&instrumented_wasm).expect("Wasm is not valid");

    instrumented_wasm
}

/// The main orchestration function for applying AFL instrumentation.
///
/// It performs the following steps:
/// 1. Injects global variables required for tracking coverage.
/// 2. Injects an `export_coverage` query function to expose the coverage map.
/// 3. Instruments all branch instructions to update the coverage map.
fn instrument_for_afl(module: &mut Module<'_>) -> Result<()> {
    let (afl_prev_loc_idx, afl_mem_ptr_idx) = inject_globals(module);
    println!(
        "  -> Injected globals: prev_loc @ index {afl_prev_loc_idx:?}, mem_ptr @ index {afl_mem_ptr_idx:?}"
    );

    inject_afl_coverage_export(module, afl_mem_ptr_idx)?;
    println!("  -> Injected `canister_query export_coverage` function.");

    instrument_branches(module, afl_prev_loc_idx, afl_mem_ptr_idx);
    println!("  -> Instrumented branch instructions in all functions.");

    Ok(())
}

/// Injects the necessary global variables for AFL instrumentation.
///
/// - `__afl_prev_loc`: A mutable i32 global to store the ID of the previously executed
///   basic block. This is used to track edges in the control flow graph.
/// - `__afl_mem_ptr`: An immutable i32 global that holds the base address (0) of the coverage map.
fn inject_globals(module: &mut Module<'_>) -> (GlobalID, GlobalID) {
    let afl_prev_loc_idx = module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I32(0))]),
        DataType::I32,
        true,
        false,
    );
    let afl_mem_ptr_idx = module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I32(0))]),
        DataType::I32,
        false,
        false,
    );
    (afl_prev_loc_idx, afl_mem_ptr_idx)
}

/// Injects the `canister_query export_coverage` function.
///
/// This exported function allows the fuzzer orchestrator to query the canister
/// and retrieve the coverage map. It uses the `ic0.msg_reply_data_append` and
/// `ic0.msg_reply` System API calls to send the contents of the coverage map
/// back to the caller.
fn inject_afl_coverage_export<'a>(
    module: &mut Module<'a>,
    afl_mem_ptr_idx: GlobalID,
) -> Result<()> {
    let (msg_reply_data_append_idx, msg_reply_idx) = ensure_ic0_imports(module)?;

    let mut func_builder = FunctionBuilder::new(&[], &[]);
    func_builder
        .global_get(afl_mem_ptr_idx)
        .i32_const(AFL_COVERAGE_MAP_SIZE)
        .call(msg_reply_data_append_idx)
        .call(msg_reply_idx);
    let coverage_function_id = func_builder.finish_module(module);

    let export_name = format!("canister_query {COVERAGE_FN_EXPORT_NAME}");
    module
        .exports
        .add_export_func(export_name, coverage_function_id.0);

    Ok(())
}

/// Instruments branch instructions in all functions of the module.
///
/// This function iterates through every instruction in every function body.
/// Before each branch-like instruction (`If`, `Else`, `Block`, `Loop`, `Br`, `BrIf`, `BrTable`),
/// it inserts an instrumentation snippet that updates the AFL coverage map.
/// A new i32 local is added to each function to facilitate the instrumentation logic.
fn instrument_branches(
    module: &mut Module<'_>,
    afl_prev_loc_idx: GlobalID,
    afl_mem_ptr_idx: GlobalID,
) {
    let mut rng = rand::thread_rng();

    for function in module.functions.iter_mut() {
        if matches!(function.kind(), FuncKind::Local(_)) {
            let local_function = function.unwrap_local_mut();
            let afl_local_idx = local_function.add_local(DataType::I32);

            let mut new_instructions = Vec::with_capacity(local_function.body.num_instructions * 2);
            new_instructions.extend(afl_instrumentation_slice(
                &mut rng,
                afl_prev_loc_idx.0,
                afl_mem_ptr_idx.0,
                afl_local_idx.0,
            ));

            for instruction in local_function.body.instructions.get_ops() {
                match instruction {
                    Operator::If { .. }
                    | Operator::Else
                    | Operator::Block { .. }
                    | Operator::Loop { .. }
                    | Operator::Br { .. }
                    | Operator::BrIf { .. }
                    | Operator::BrTable { .. } => {
                        new_instructions.extend(afl_instrumentation_slice(
                            &mut rng,
                            afl_prev_loc_idx.0,
                            afl_mem_ptr_idx.0,
                            afl_local_idx.0,
                        ));
                        new_instructions.push(instruction.clone());
                    }
                    _ => new_instructions.push(instruction.clone()),
                }
            }
            local_function.body.instructions = Instructions::new(new_instructions);
        }
    }
}

/// Generates the sequence of Wasm operators for AFL instrumentation.
///
/// This is a Rust implementation of the standard AFL instrumentation logic:
/// ```c
///   cur_location = <COMPILE_TIME_RANDOM>;
///   shared_mem[cur_location ^ prev_location]++;
///   prev_location = cur_location >> 1;
/// ```
/// It uses the provided global and local variable indices to generate the
/// corresponding Wasm instructions.
fn afl_instrumentation_slice(
    rng: &mut impl Rng,
    afl_prev_loc_idx: u32,
    afl_mem_ptr_idx: u32,
    afl_local_idx: u32,
) -> Vec<Operator<'static>> {
    let curr_location = rng.gen_range(0..AFL_COVERAGE_MAP_SIZE);
    vec![
        Operator::I32Const {
            value: curr_location,
        },
        Operator::GlobalGet {
            global_index: afl_prev_loc_idx,
        },
        Operator::I32Xor,
        Operator::GlobalGet {
            global_index: afl_mem_ptr_idx,
        },
        Operator::I32Add,
        Operator::LocalTee {
            local_index: afl_local_idx,
        },
        Operator::LocalGet {
            local_index: afl_local_idx,
        },
        Operator::I32Load8U {
            memarg: MemArg {
                offset: 0,
                align: 0,
                memory: 0,
                max_align: 0,
            },
        },
        Operator::I32Const { value: 1 },
        Operator::I32Add,
        Operator::I32Store8 {
            memarg: MemArg {
                offset: 0,
                align: 0,
                memory: 0,
                max_align: 0,
            },
        },
        Operator::I32Const {
            value: curr_location >> 1,
        },
        Operator::GlobalSet {
            global_index: afl_prev_loc_idx,
        },
    ]
}

/// Ensures that the necessary `ic0` System API functions are imported.
///
/// The instrumentation requires `ic0.msg_reply_data_append` and `ic0.msg_reply`
/// for the `export_coverage` function. This function checks if they are already
/// imported. If not, it adds them to the module's import section.
/// It returns the function indices for both imports.
fn ensure_ic0_imports(module: &mut Module<'_>) -> Result<(FunctionID, FunctionID)> {
    let mut data_append_idx = module.imports.get_func(
        API_VERSION_IC0.to_string(),
        "msg_reply_data_append".to_string(),
    );
    let mut reply_idx = module
        .imports
        .get_func(API_VERSION_IC0.to_string(), "msg_reply".to_string());

    if data_append_idx.is_none() {
        let type_id = module
            .types
            .add_func_type(&[DataType::I32, DataType::I32], &[]);
        let (func_index, _) = module.add_import_func(
            API_VERSION_IC0.to_string(),
            "msg_reply_data_append".to_string(),
            type_id,
        );
        data_append_idx = Some(func_index);
    }

    if reply_idx.is_none() {
        let type_id = module.types.add_func_type(&[], &[]);
        let (func_index, _) = module.add_import_func(
            API_VERSION_IC0.to_string(),
            "msg_reply".to_string(),
            type_id,
        );
        reply_idx = Some(func_index);
    }

    Ok((data_append_idx.unwrap(), reply_idx.unwrap()))
}

/// Validates the instrumented Wasm module.
///
/// Uses `wasmparser::Validator` to ensure that the transformations have resulted in a valid Wasm module.
fn validate_wasm(wasm_bytes: &[u8]) -> Result<()> {
    let mut validator = Validator::new();
    validator.validate_all(wasm_bytes)?;
    println!("Validation of instrumented Wasm successful.");
    Ok(())
}
