//! This module provides functionality to instrument WebAssembly (Wasm) modules
//! for coverage-guided fuzzing, specifically implementing an AFL-style instrumentation.
//!
//! The primary goal is to inject code into a Wasm module that tracks execution paths.
//! This is achieved by:
//! 1.  Injecting global variables to maintain state, such as the previous location.
//! 2.  Injecting a helper function that contains the core instrumentation logic.
//! 3.  Instrumenting the Wasm bytecode by inserting calls to the helper function at the
//!     start of each function and before every branch, effectively covering all basic blocks.
//! 4.  Exporting a coverage function that allows the fuzzer to retrieve the
//!     coverage map from the canister.

use anyhow::Result;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use wirm::ir::function::FunctionBuilder;
use wirm::ir::id::{FunctionID, GlobalID, LocalID};
use wirm::ir::module::module_functions::FuncKind;
use wirm::ir::types::{InitExpr, Instructions, Value};
use wirm::module_builder::AddLocal;
use wirm::wasmparser::{MemArg, Operator, Validator};
use wirm::{DataType, InitInstr, Module, Opcode};

use crate::constants::{AFL_COVERAGE_MAP_SIZE, API_VERSION_IC0, COVERAGE_FN_EXPORT_NAME};

/// A global, mutable static array to hold the coverage map.
///
/// # Safety
///
/// This is a raw pointer to a mutable static memory region, which is inherently `unsafe`.
/// It is used as a shared memory region between the fuzzer and the instrumented canister.
/// The `libafl` framework is designed to work with such a mechanism, which is a highly
/// optimized approach for coverage-guided fuzzing, inspired by AFL.
pub static mut COVERAGE_MAP: &mut [u8] = &mut [0; AFL_COVERAGE_MAP_SIZE as usize];

/// Instruments the given Wasm bytes for fuzzing.
///
/// This function takes a raw Wasm module, applies AFL-style instrumentation for
/// coverage tracking, and returns the instrumented Wasm module as a vector of bytes.
/// The resulting Wasm is validated before being returned.
///
/// # Arguments
///
/// * `wasm_bytes` - The raw Wasm module to instrument.
/// * `history_size` - The number of previous locations to track (must be 1, 2, 4, or 8).
pub fn instrument_wasm_for_fuzzing(wasm_bytes: &[u8], history_size: usize) -> Vec<u8> {
    assert!(
        matches!(history_size, 1 | 2 | 4 | 8),
        "History size must be 1, 2, 4, or 8"
    );
    let mut module = Module::parse(wasm_bytes, false).expect("Failed to parse module with wirm");

    instrument_for_afl(&mut module, history_size)
        .expect("Unable to instrument wasm module for AFL");

    // Sorry it has to be this way :(
    let buf = vec![0u8; AFL_COVERAGE_MAP_SIZE as usize * history_size].into_boxed_slice();
    let buf: &'static mut [u8] = Box::leak(buf);
    unsafe {
        COVERAGE_MAP = buf;
    }

    let instrumented_wasm = module.encode();

    validate_wasm(&instrumented_wasm).expect("Wasm is not valid");

    instrumented_wasm
}

/// The main orchestration function for applying AFL instrumentation.
///
/// It performs the following steps:
/// 1. Injects global variables required for tracking coverage.
/// 2. Injects the `[COVERAGE_FN_EXPORT_NAME]` update function to expose the coverage map.
/// 3. Instruments all functions by inserting calls to a helper function at the
///    start of each function and before each branch instruction.
fn instrument_for_afl(module: &mut Module<'_>, history_size: usize) -> Result<()> {
    let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(module, history_size);
    println!(
        "  -> Injected globals: prev_locs @ indices {afl_prev_loc_indices:?}, mem_ptr @ index {afl_mem_ptr_idx:?}"
    );

    inject_afl_coverage_export(module, history_size, afl_mem_ptr_idx)?;
    println!("  -> Injected `canister_update __export_coverage_for_afl` function.");

    instrument_branches(module, &afl_prev_loc_indices, afl_mem_ptr_idx);
    println!("  -> Instrumented branch instructions in all functions.");

    Ok(())
}

/// Injects the necessary global variables for AFL instrumentation.
///
/// - `__afl_prev_loc_N`: A set of `history_size` mutable i32 globals to store the IDs
///   of the previously executed basic blocks. This is used to track execution history
///   in the control flow graph.
/// - `__afl_mem_ptr`: An immutable i32 global that holds the base address (0) of the coverage map.
fn inject_globals(module: &mut Module<'_>, history_size: usize) -> (Vec<GlobalID>, GlobalID) {
    let mut afl_prev_loc_indices = Vec::with_capacity(history_size);
    for _ in 0..history_size {
        let global_id = module.add_global(
            InitExpr::new(vec![InitInstr::Value(Value::I32(0))]),
            DataType::I32,
            true,
            false,
        );
        afl_prev_loc_indices.push(global_id);
    }
    let afl_mem_ptr_idx = module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I32(0))]),
        DataType::I32,
        false,
        false,
    );
    (afl_prev_loc_indices, afl_mem_ptr_idx)
}

/// Injects the `canister_update `[COVERAGE_FN_EXPORT_NAME]` function.
///
/// This exported function allows the fuzzer orchestrator to read the canister,
/// retrieve the coverage map and reset it. It uses the `ic0.msg_reply_data_append` and
/// `ic0.msg_reply` System API calls to send the contents of the coverage map
/// back to the caller.
fn inject_afl_coverage_export<'a>(
    module: &mut Module<'a>,
    history_size: usize,
    afl_mem_ptr_idx: GlobalID,
) -> Result<()> {
    let (msg_reply_data_append_idx, msg_reply_idx) = ensure_ic0_imports(module)?;

    let mut func_builder = FunctionBuilder::new(&[], &[]);
    func_builder
        .global_get(afl_mem_ptr_idx)
        .i32_const(AFL_COVERAGE_MAP_SIZE * history_size as i32)
        .call(msg_reply_data_append_idx)
        .call(msg_reply_idx)
        .global_get(afl_mem_ptr_idx)
        .i32_const(0)
        .i32_const(AFL_COVERAGE_MAP_SIZE * history_size as i32)
        .memory_fill(0);

    let coverage_function_id = func_builder.finish_module(module);

    let export_name = format!("canister_update {COVERAGE_FN_EXPORT_NAME}");
    module
        .exports
        .add_export_func(export_name, coverage_function_id.0);

    Ok(())
}

/// Instruments all local functions in the module to track code coverage.
///
/// This function iterates through every instruction in every function body.
/// It inserts a call to a helper instrumentation function at the beginning of the function
/// and before each branch-like instruction (`If`, `Else`, `Block`, `Loop`, `Br`, `BrIf`, `BrTable`).
/// This ensures that every basic block is instrumented.
fn instrument_branches(
    module: &mut Module<'_>,
    afl_prev_loc_indices: &[GlobalID],
    afl_mem_ptr_idx: GlobalID,
) {
    let instrumentation_function =
        afl_instrumentation_slice(module, afl_prev_loc_indices, afl_mem_ptr_idx);
    let seed: u32 = rand::thread_rng().next_u32();
    println!("The seed used for instrumentation is {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);

    let mut create_instrumentation_ops = |ops: &mut Vec<Operator>| {
        let curr_location = rng.gen_range(0..AFL_COVERAGE_MAP_SIZE as i32);
        ops.push(Operator::I32Const {
            value: curr_location,
        });
        ops.push(Operator::Call {
            function_index: instrumentation_function.0,
        });
    };

    for (function_index, function) in module.functions.iter_mut().enumerate() {
        if matches!(function.kind(), FuncKind::Local(_))
            && FunctionID(function_index as u32) != instrumentation_function
        {
            let local_function = function.unwrap_local_mut();
            let mut new_instructions = Vec::with_capacity(local_function.body.num_instructions * 2);

            create_instrumentation_ops(&mut new_instructions);

            for instruction in local_function.body.instructions.get_ops() {
                match instruction {
                    Operator::Block { .. }
                    | Operator::Loop { .. }
                    | Operator::If { .. }
                    | Operator::Else => {
                        new_instructions.push(instruction.clone());
                        create_instrumentation_ops(&mut new_instructions);
                    }
                    Operator::Br { .. }
                    | Operator::BrIf { .. }
                    | Operator::BrTable { .. }
                    | Operator::Return => {
                        create_instrumentation_ops(&mut new_instructions);
                        new_instructions.push(instruction.clone());
                    }
                    _ => new_instructions.push(instruction.clone()),
                }
            }
            local_function.body.instructions = Instructions::new(new_instructions);
        }
    }
}

/// Creates and injects a helper function that contains the core AFL instrumentation logic.
///
/// This function will be called from instrumented locations (start of functions, before branches).
/// It implements the standard AFL coverage tracking mechanism:
/// ```text
///   curr_location = <COMPILE_TIME_RANDOM>;
///   key = curr_location ^ prev_loc[0] ^ ... ^ prev_loc[history_size-1];
///   shared_mem[key]++;
///   prev_loc[history_size-1] = prev_loc[history_size-2] >> 1;
///   ...
///   prev_loc[0] = curr_location >> 1;
/// ```
/// The generated function takes the current location (`curr_location`) as an i32 parameter
/// and is added to the module.
///
/// # Returns
///
/// The `FunctionID` of the newly created helper function.
fn afl_instrumentation_slice(
    module: &mut Module<'_>,
    afl_prev_loc_indices: &[GlobalID],
    afl_mem_ptr_idx: GlobalID,
) -> FunctionID {
    let mut func_builder = FunctionBuilder::new(&[DataType::I32], &[]);
    let curr_location = LocalID(0);
    let afl_local_idx = func_builder.add_local(DataType::I32);

    func_builder.local_get(curr_location);
    for &prev_loc_idx in afl_prev_loc_indices {
        func_builder.global_get(prev_loc_idx).i32_xor();
    }

    func_builder
        .global_get(afl_mem_ptr_idx)
        .i32_add()
        .local_tee(afl_local_idx)
        .local_get(afl_local_idx)
        .i32_load8_u(MemArg {
            offset: 0,
            align: 0,
            memory: 0,
            max_align: 0,
        })
        .i32_const(1)
        .i32_add()
        .i32_store8(MemArg {
            offset: 0,
            align: 0,
            memory: 0,
            max_align: 0,
        });

    // Shift the history
    for i in (1..afl_prev_loc_indices.len()).rev() {
        func_builder
            .global_get(afl_prev_loc_indices[i - 1])
            .i32_const(1)
            .i32_shr_unsigned()
            .global_set(afl_prev_loc_indices[i]);
    }

    func_builder
        .local_get(curr_location)
        .i32_const(1)
        .i32_shr_unsigned()
        .global_set(afl_prev_loc_indices[0]);

    func_builder.finish_module(module)
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
