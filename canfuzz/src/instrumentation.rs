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

/// Arguments for configuring the Wasm instrumentation process.
pub struct InstrumentationArgs {
    /// The raw Wasm module to instrument.
    pub wasm_bytes: Vec<u8>,
    /// The number of previous locations to track (must be 1, 2, 4, or 8).
    pub history_size: usize,
    /// The seed to use for instrumentation.
    pub seed: Seed,
}

/// Specifies the seed for the random number generator used during instrumentation.
///
/// Using a static seed allows for deterministic and reproducible instrumentation,
/// which is crucial for debugging and consistent testing environments.
#[derive(Copy, Clone, Debug)]
pub enum Seed {
    /// A randomly generated seed will be used.
    Random,
    /// A user-provided static seed will be used.
    Static(u32),
}
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
/// * `instrumentation_args` - A struct containing the Wasm bytes, history size, and instrumentation seed.
pub fn instrument_wasm_for_fuzzing(instrumentation_args: InstrumentationArgs) -> Vec<u8> {
    assert!(
        matches!(instrumentation_args.history_size, 1 | 2 | 4 | 8),
        "History size must be 1, 2, 4, or 8"
    );
    let mut module = Module::parse(&instrumentation_args.wasm_bytes, false, false)
        .expect("Failed to parse module with wirm");

    instrument_for_afl(&mut module, &instrumentation_args)
        .expect("Unable to instrument wasm module for AFL");

    // Sorry it has to be this way :(
    let buf = vec![0u8; AFL_COVERAGE_MAP_SIZE as usize * instrumentation_args.history_size]
        .into_boxed_slice();
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
fn instrument_for_afl(
    module: &mut Module<'_>,
    instrumentation_args: &InstrumentationArgs,
) -> Result<()> {
    let (afl_prev_loc_indices, afl_mem_ptr_idx) =
        inject_globals(module, instrumentation_args.history_size);
    println!(
        "  -> Injected globals: prev_locs @ indices {afl_prev_loc_indices:?}, mem_ptr @ index {afl_mem_ptr_idx:?}"
    );

    inject_afl_coverage_export(module, instrumentation_args.history_size, afl_mem_ptr_idx)?;
    println!("  -> Injected `canister_update __export_coverage_for_afl` function.");

    instrument_branches(
        module,
        &afl_prev_loc_indices,
        afl_mem_ptr_idx,
        instrumentation_args.seed,
    );
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
    seed: Seed,
) {
    let instrumentation_function =
        afl_instrumentation_slice(module, afl_prev_loc_indices, afl_mem_ptr_idx);

    let seed = match seed {
        Seed::Random => rand::rng().next_u32(),
        Seed::Static(s) => s,
    };
    println!("The seed used for instrumentation is {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);

    let mut create_instrumentation_ops = |ops: &mut Vec<Operator>| {
        let curr_location =
            rng.random_range(0..AFL_COVERAGE_MAP_SIZE * afl_prev_loc_indices.len() as i32);
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
            // offsets are set to zero, as we are not interested in preserving them.
            local_function.body.instructions = Instructions::new(
                new_instructions.iter().map(|i| (i.clone(), 0)).collect(),
                0,
                false,
            );
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

#[cfg(test)]
mod tests {
    use wirm::{ir::module::module_globals::GlobalKind, wasmparser::ValType};

    use super::*;
    #[test]
    fn inject_globals_empty_module() {
        let wat = wat::parse_str(
            r#"
                (module)
            "#,
        )
        .unwrap();

        let history_range: [usize; 4] = [1, 2, 4, 8];
        for history_size in history_range {
            let mut module = Module::parse(&wat, false, false).unwrap();
            let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);

            assert_eq!(afl_prev_loc_indices.len(), history_size);
            (0..history_size)
                .for_each(|index| assert_eq!(afl_prev_loc_indices[index], GlobalID(index as u32)));
            assert_eq!(afl_mem_ptr_idx, GlobalID(history_size as u32));
        }
    }

    #[test]
    fn inject_globals_two_globals() {
        let wat = wat::parse_str(
            r#"
                (module
                    (global (;0;) (mut i32) i32.const 0)
                    (global (;1;) (mut i32) i32.const 0)
                )
            "#,
        )
        .unwrap();

        let offset: u32 = 2;

        let history_range: [usize; 4] = [1, 2, 4, 8];
        for history_size in history_range {
            let mut module = Module::parse(&wat, false, false).unwrap();
            let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);

            assert_eq!(afl_prev_loc_indices.len(), history_size);
            (0..history_size).for_each(|index| {
                assert_eq!(afl_prev_loc_indices[index], GlobalID(index as u32 + offset))
            });
            assert_eq!(afl_mem_ptr_idx, GlobalID(history_size as u32 + offset));
        }
    }

    #[test]
    fn inject_globals_check_global_values() {
        let wat = wat::parse_str(
            r#"
                (module
                    (global (;0;) (mut i32) i32.const 0)
                    (global (;1;) (mut i32) i32.const 0)
                )
            "#,
        )
        .unwrap();

        let validate_global = |global: GlobalKind, mutable: bool| {
            assert_matches::assert_matches!(global, GlobalKind::Local(_));
            if let GlobalKind::Local(local) = global {
                assert_eq!(local.ty.content_type, ValType::I32);
                assert_eq!(local.ty.mutable, mutable);
                assert!(!local.ty.shared);
                assert_eq!(local.init_expr.instructions().len(), 1);
                assert_matches::assert_matches!(
                    local.init_expr.instructions()[0],
                    InitInstr::Value(Value::I32(0))
                );
            }
        };

        let history_range: [usize; 4] = [1, 2, 4, 8];
        for history_size in history_range {
            let mut module = Module::parse(&wat, false, false).unwrap();
            let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);

            for g in afl_prev_loc_indices.iter() {
                let global = module.globals.get_kind(*g);
                validate_global(global.clone(), true);
            }
            let global = module.globals.get_kind(afl_mem_ptr_idx);
            validate_global(global.clone(), false);
        }
    }

    #[test]
    fn inject_ic0_imports_empty_module() {
        let wat = wat::parse_str(
            r#"
                (module)
            "#,
        )
        .unwrap();

        let mut module = Module::parse(&wat, false, false).unwrap();
        let (data_append_idx, reply_idx) = ensure_ic0_imports(&mut module).unwrap();

        assert_eq!(data_append_idx, FunctionID(0));
        assert_eq!(reply_idx, FunctionID(1));
    }

    #[test]
    fn inject_ic0_imports_one_import() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i32)))
                    (import "ic0" "dummy" (func (;0;) (type 0)))
                )
            "#,
        )
        .unwrap();

        let mut module = Module::parse(&wat, false, false).unwrap();
        let (data_append_idx, reply_idx) = ensure_ic0_imports(&mut module).unwrap();

        assert_eq!(data_append_idx, FunctionID(1));
        assert_eq!(reply_idx, FunctionID(2));
    }

    #[test]
    fn inject_ic0_imports_data_append_exists() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i32 i32)))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 0)))
                )
            "#,
        )
        .unwrap();

        let mut module = Module::parse(&wat, false, false).unwrap();
        let (data_append_idx, reply_idx) = ensure_ic0_imports(&mut module).unwrap();

        assert_eq!(data_append_idx, FunctionID(0));
        assert_eq!(reply_idx, FunctionID(1));
    }

    #[test]
    fn inject_ic0_imports_reply_exists() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func))
                    (import "ic0" "msg_reply" (func (;0;) (type 0)))
                )
            "#,
        )
        .unwrap();

        let mut module = Module::parse(&wat, false, false).unwrap();
        let (data_append_idx, reply_idx) = ensure_ic0_imports(&mut module).unwrap();

        assert_eq!(data_append_idx, FunctionID(1));
        assert_eq!(reply_idx, FunctionID(0));
    }

    #[test]
    fn inject_ic0_imports_both_exists() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i32 i32)))
                    (type (;1;) (func))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 0)))
                    (import "ic0" "msg_reply" (func (;1;) (type 1)))
                )
            "#,
        )
        .unwrap();

        let mut module = Module::parse(&wat, false, false).unwrap();
        let (data_append_idx, reply_idx) = ensure_ic0_imports(&mut module).unwrap();

        assert_eq!(data_append_idx, FunctionID(0));
        assert_eq!(reply_idx, FunctionID(1));
    }

    fn wasm_equality(generated: Vec<u8>, expected: Vec<u8>) {
        // both are encoded slices
        if generated != expected {
            let generated_text = wasmprinter::print_bytes(&generated).unwrap();
            let expected_text = wasmprinter::print_bytes(&expected).unwrap();
            // It's nice to show textual diffs
            difference::assert_diff!(generated_text.as_str(), expected_text.as_str(), "\n", 0)
        }
    }

    #[test]
    fn inject_instrumentation_function_empty_module() {
        let wat = wat::parse_str(
            r#"
                (module
                    (memory (;0;) 1)
                )
            "#,
        )
        .unwrap();

        let history_size = 2;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);
        let instrumentation_function =
            afl_instrumentation_slice(&mut module, &afl_prev_loc_indices, afl_mem_ptr_idx);
        assert_eq!(instrumentation_function, FunctionID(0));
        let expected_wasm = wat::parse_str(
            r#"(module
                            (type (;0;) (func (param i32)))
                            (memory (;0;) 1)
                            (global (;0;) (mut i32) i32.const 0)
                            (global (;1;) (mut i32) i32.const 0)
                            (global (;2;) i32 i32.const 0)
                            (func (;0;) (type 0) (param i32)
                                (local i32)
                                local.get 0
                                global.get 0
                                i32.xor
                                global.get 1
                                i32.xor
                                global.get 2
                                i32.add
                                local.tee 1
                                local.get 1
                                i32.load8_u
                                i32.const 1
                                i32.add
                                i32.store8
                                global.get 0
                                i32.const 1
                                i32.shr_u
                                global.set 1
                                local.get 0
                                i32.const 1
                                i32.shr_u
                                global.set 0
                            )
                        )"#,
        )
        .unwrap();
        let mut expected_module = Module::parse(&expected_wasm, false, false).unwrap();
        wasm_equality(module.encode(), expected_module.encode());
    }

    #[test]
    fn inject_afl_coverage_export_empty_module() {
        let wat = wat::parse_str(
            r#"
                (module
                    (memory (;0;) 1)
                )
            "#,
        )
        .unwrap();

        let history_size = 2;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (_, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);
        let coverage_function =
            inject_afl_coverage_export(&mut module, history_size, afl_mem_ptr_idx);
        assert!(coverage_function.is_ok());
        let expected_wasm = wat::parse_str(
            r#"(module
                    (type (;0;) (func (param i32 i32)))
                    (type (;1;) (func))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 0)))
                    (import "ic0" "msg_reply" (func (;1;) (type 1)))
                    (memory (;0;) 1)
                    (global (;0;) (mut i32) i32.const 0)
                    (global (;1;) (mut i32) i32.const 0)
                    (global (;2;) i32 i32.const 0)
                    (export "canister_update __export_coverage_for_afl" (func 2))
                    (func (;2;) (type 1)
                        global.get 2
                        i32.const 131072
                        call 0
                        call 1
                        global.get 2
                        i32.const 0
                        i32.const 131072
                        memory.fill
                    )
                )"#,
        )
        .unwrap();
        let mut expected_module = Module::parse(&expected_wasm, false, false).unwrap();
        wasm_equality(module.encode(), expected_module.encode());
    }

    /// Helper function to test branching instrumentation.
    fn instrument_branches_helper(module: &str, expected: &[Operator]) {
        let wat = wat::parse_str(module).unwrap();

        let history_size = 2;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);
        instrument_branches(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            Seed::Static(42),
        );

        let instructions = module
            .functions
            .get_fn_by_id(FunctionID(0))
            .unwrap()
            .unwrap_local()
            .body
            .instructions
            .get_ops();

        assert_eq!(instructions, expected);
    }

    #[test]
    fn inject_branch_instrumentation_one_func() {
        instrument_branches_helper(
            r#"
                (module
                    (type (;0;) (func))
                    (memory (;0;) 1)
                    (func (;0;) (type 0))
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_block() {
        instrument_branches_helper(
            r#"
                (module
                    (memory (;0;) 1)
                    (func
                        block
                        nop
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::Block {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::Nop,
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_loop() {
        instrument_branches_helper(
            r#"
                (module
                    (memory (;0;) 1)
                    (func
                        loop
                        nop
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::Loop {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::Nop,
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_if() {
        instrument_branches_helper(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        i32.const 0  ;; Condition
                        if
                        nop
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::I32Const { value: 0 },
                Operator::If {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::Nop,
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_if_else() {
        instrument_branches_helper(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        i32.const 0
                        if
                        nop
                        else
                        nop
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::I32Const { value: 0 },
                Operator::If {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::Nop,
                Operator::Else,
                Operator::I32Const { value: 32602 },
                Operator::Call { function_index: 1 },
                Operator::Nop,
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_br() {
        instrument_branches_helper(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        block
                        br 0
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::Block {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::I32Const { value: 32602 },
                Operator::Call { function_index: 1 },
                Operator::Br { relative_depth: 0 },
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_brif() {
        instrument_branches_helper(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        block
                        i32.const 0
                        br_if 0
                        end
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::Block {
                    blockty: wirm::wasmparser::BlockType::Empty,
                },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::I32Const { value: 0 },
                Operator::I32Const { value: 32602 },
                Operator::Call { function_index: 1 },
                Operator::BrIf { relative_depth: 0 },
                Operator::End,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_return() {
        instrument_branches_helper(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        return
                    )
                )
            "#,
            &[
                Operator::I32Const { value: 17486 },
                Operator::Call { function_index: 1 },
                Operator::I32Const { value: 69016 },
                Operator::Call { function_index: 1 },
                Operator::Return,
                Operator::End,
            ],
        );
    }

    #[test]
    fn inject_branch_instrumentation_one_func_one_brtable() {
        let wat = wat::parse_str(
            r#"
               (module
                    (memory (;0;) 1)
                    (func
                        block
                        i32.const 0
                        br_table 0 0
                        end
                    )
                )
            "#,
        )
        .unwrap();

        let history_size = 2;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (afl_prev_loc_indices, afl_mem_ptr_idx) = inject_globals(&mut module, history_size);
        instrument_branches(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            Seed::Static(42),
        );

        let instructions = module
            .functions
            .get_fn_by_id(FunctionID(0))
            .unwrap()
            .unwrap_local()
            .body
            .instructions
            .get_ops();

        let exptected = vec![
            Operator::I32Const { value: 17486 },
            Operator::Call { function_index: 1 },
            Operator::Block {
                blockty: wirm::wasmparser::BlockType::Empty,
            },
            Operator::I32Const { value: 69016 },
            Operator::Call { function_index: 1 },
            Operator::I32Const { value: 0 },
            Operator::I32Const { value: 32602 },
            Operator::Call { function_index: 1 },
            // BrTable fields are private, so it can't be hardcoded.
            Operator::End,
            Operator::End,
        ];

        assert_eq!(
            instructions
                .iter()
                .filter(|o| !matches!(o, Operator::BrTable { targets: _ }))
                .cloned()
                .collect::<Vec<_>>(),
            exptected
        );
    }
}
