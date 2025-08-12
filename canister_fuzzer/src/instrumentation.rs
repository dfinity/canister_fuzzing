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
use ic_wasm_transform::{Body, Global, Module};
use rand::Rng;
use wasmparser::CompositeType;
use wasmparser::{Export, ExternalKind, FuncType, Import, Operator, SubType, TypeRef, ValType};

use crate::constants::{AFL_COVERAGE_MAP_SIZE, API_VERSION_IC0};

/// Instruments the given Wasm bytes for fuzzing.
///
/// This function takes a raw Wasm module, applies AFL-style instrumentation for
/// coverage tracking, and returns the instrumented Wasm module as a vector of bytes.
/// The resulting Wasm is validated before being returned.
pub fn instrument_wasm_for_fuzzing(wasm_bytes: &[u8]) -> Vec<u8> {
    let mut module =
        Module::parse(wasm_bytes, false).expect("Failed to parse module with ic-wasm-transform");

    instrument_for_afl(&mut module).expect("Unable to instrument wasm module for AFL");

    let instrumented_wasm = module
        .encode()
        .expect("Unable to encode module with ic-wasm-transform");

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
        "  -> Injected globals: prev_loc @ index {afl_prev_loc_idx}, mem_ptr @ index {afl_mem_ptr_idx}"
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
fn inject_globals(module: &mut Module<'_>) -> (u32, u32) {
    let afl_prev_loc_idx = module.globals.len() as u32;
    let prev_location = Global {
        ty: wasmparser::GlobalType {
            content_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        init_expr: Operator::I32Const { value: 0 },
    };
    module.globals.push(prev_location);

    let afl_mem_ptr_idx = module.globals.len() as u32;
    let mem_ptr = Global {
        ty: wasmparser::GlobalType {
            content_type: ValType::I32,
            mutable: false,
            shared: false,
        },
        init_expr: Operator::I32Const { value: 0 },
    };
    module.globals.push(mem_ptr);

    (afl_prev_loc_idx, afl_mem_ptr_idx)
}

/// Injects the `canister_query export_coverage` function.
///
/// This exported function allows the fuzzer orchestrator to query the canister
/// and retrieve the coverage map. It uses the `ic0.msg_reply_data_append` and
/// `ic0.msg_reply` System API calls to send the contents of the coverage map
/// back to the caller.
fn inject_afl_coverage_export(module: &mut Module<'_>, afl_mem_ptr_idx: u32) -> Result<()> {
    let (msg_reply_data_append_idx, msg_reply_idx) = ensure_ic0_imports(module)?;

    let ty = FuncType::new([], []);
    let type_idx = add_func_type(module, ty);
    module.functions.push(type_idx);

    let func_body = Body {
        locals: vec![],
        instructions: vec![
            Operator::GlobalGet {
                global_index: afl_mem_ptr_idx,
            },
            Operator::I32Const {
                value: AFL_COVERAGE_MAP_SIZE,
            },
            Operator::Call {
                function_index: msg_reply_data_append_idx,
            },
            Operator::Call {
                function_index: msg_reply_idx,
            },
            Operator::End,
        ],
    };
    module.code_sections.push(func_body);

    let new_func_index = (module.imports.len() + module.functions.len() - 1) as u32;
    let export = Export {
        name: "canister_query export_coverage",
        kind: ExternalKind::Func,
        index: new_func_index,
    };
    module.exports.push(export);

    Ok(())
}

/// Instruments branch instructions in all functions of the module.
///
/// This function iterates through every instruction in every function body.
/// Before each branch-like instruction (`If`, `Else`, `Block`, `Loop`, `Br`, `BrIf`, `BrTable`),
/// it inserts an instrumentation snippet that updates the AFL coverage map.
/// A new i32 local is added to each function to facilitate the instrumentation logic.
fn instrument_branches(module: &mut Module<'_>, afl_prev_loc_idx: u32, afl_mem_ptr_idx: u32) {
    let mut rng = rand::thread_rng();

    for (func_idx, body) in module.code_sections.iter_mut().enumerate() {
        let type_idx = module.functions[func_idx];
        let num_params = if let Some(subtype) = module.types.get(type_idx as usize) {
            if let CompositeType {
                inner: wasmparser::CompositeInnerType::Func(func_type),
                ..
            } = &subtype.composite_type
            {
                func_type.params().len() as u32
            } else {
                panic!("Type at index {type_idx} is not a function type");
            }
        } else {
            panic!("Could not find type for function index {func_idx}");
        };

        let afl_local_idx = add_i32_local(body, num_params);

        let mut new_instructions = Vec::with_capacity(body.instructions.len() * 2);
        new_instructions.extend(afl_instrumentation_slice(
            &mut rng,
            afl_prev_loc_idx,
            afl_mem_ptr_idx,
            afl_local_idx,
        ));

        for instruction in body.instructions.iter() {
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
                        afl_prev_loc_idx,
                        afl_mem_ptr_idx,
                        afl_local_idx,
                    ));
                    new_instructions.push(instruction.clone());
                }
                _ => new_instructions.push(instruction.clone()),
            }
        }
        body.instructions = new_instructions;
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
            memarg: wasmparser::MemArg {
                offset: 0,
                align: 0,
                memory: 0,
                max_align: 0,
            },
        },
        Operator::I32Const { value: 1 },
        Operator::I32Add,
        Operator::I32Store8 {
            memarg: wasmparser::MemArg {
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

/// Adds a new `i32` local variable to a function body.
///
/// It calculates the index for the new local, accounting for existing parameters and locals.
fn add_i32_local(body: &mut Body, num_params: u32) -> u32 {
    let existing_locals_count: u32 = body.locals.iter().map(|(count, _)| *count).sum();
    let new_local_index = num_params + existing_locals_count;
    body.locals.push((1, ValType::I32));
    new_local_index
}

/// Adds a function type to the module's type section if it doesn't already exist.
///
/// This is a utility function to avoid duplicating function types. If an identical
/// function type is already present, its index is returned. Otherwise, the new
/// type is added, and its new index is returned.
fn add_func_type(module: &mut Module<'_>, ty: FuncType) -> u32 {
    let subtype = SubType {
        is_final: true,
        supertype_idx: None,
        composite_type: CompositeType {
            inner: wasmparser::CompositeInnerType::Func(ty),
            shared: false,
        },
    };
    if let Some(pos) = module.types.iter().position(|t| t == &subtype) {
        return pos as u32;
    }
    module.types.push(subtype);
    (module.types.len() - 1) as u32
}

/// Ensures that the necessary `ic0` System API functions are imported.
///
/// The instrumentation requires `ic0.msg_reply_data_append` and `ic0.msg_reply`
/// for the `export_coverage` function. This function checks if they are already
/// imported. If not, it adds them to the module's import section.
/// It returns the function indices for both imports.
fn ensure_ic0_imports(module: &mut Module<'_>) -> Result<(u32, u32)> {
    let mut data_append_idx = None;
    let mut reply_idx = None;
    for (i, import) in module.imports.iter().enumerate() {
        if import.module == API_VERSION_IC0 {
            if import.name == "msg_reply_data_append" {
                data_append_idx = Some(i as u32);
            }
            if import.name == "msg_reply" {
                reply_idx = Some(i as u32);
            }
        }
    }

    let final_mrda_idx = data_append_idx.unwrap_or_else(|| {
        let ty = FuncType::new([ValType::I32, ValType::I32], []);
        let type_idx = add_func_type(module, ty);
        let new_import = Import {
            module: API_VERSION_IC0,
            name: "msg_reply_data_append",
            ty: TypeRef::Func(type_idx),
        };
        let new_idx = module.imports.len() as u32;
        module.imports.push(new_import);
        new_idx
    });
    let final_mr_idx = reply_idx.unwrap_or_else(|| {
        let ty = FuncType::new([], []);
        let type_idx = add_func_type(module, ty);
        let new_import = Import {
            module: API_VERSION_IC0,
            name: "msg_reply",
            ty: TypeRef::Func(type_idx),
        };
        let new_idx = module.imports.len() as u32;
        module.imports.push(new_import);
        new_idx
    });

    Ok((final_mrda_idx, final_mr_idx))
}

/// Validates the instrumented Wasm module.
///
/// Uses `wasmparser::Validator` to ensure that the transformations have resulted in a valid Wasm module.
fn validate_wasm(wasm_bytes: &[u8]) -> Result<()> {
    let mut validator = wasmparser::Validator::new();
    validator.validate_all(wasm_bytes)?;
    println!("Validation of instrumented Wasm successful.");
    Ok(())
}
