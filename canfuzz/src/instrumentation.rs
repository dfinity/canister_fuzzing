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
//!
//! ## Instruction Count Instrumentation
//!
//! When [`InstrumentationArgs::instrument_instruction_count`] is enabled, the module also
//! performs instruction-count instrumentation via `ic0.performance_counter`. This allows the
//! fuzzer to maximize the number of IC instructions consumed by canister methods, without
//! requiring any changes to the target canister's source code.
//!
//! The instruction counting works by:
//! 1.  Wrapping each `canister_update` / `canister_query` export in a new function that
//!     reads `ic0.performance_counter(1)` after the original method returns.
//! 2.  Subtracting the estimated overhead of AFL instrumentation (computed from the IC
//!     instruction cost model and `history_size`) to isolate the canister's own cost.
//! 3.  Exporting a [`INSTRUCTION_COUNT_FN_EXPORT_NAME`](crate::constants::INSTRUCTION_COUNT_FN_EXPORT_NAME)
//!     function that replies with the 8-byte little-endian instruction count.
//!
//! ### Limitations
//!
//! - **Trapped executions report 0 instructions.** The wrapper function runs *after* the
//!   original method returns. If execution never reaches that point, the instruction count
//!   global keeps its previous value (reset to 0 at the start of each wrapper call). Traps
//!   can originate from several sources:
//!   - **Explicit traps:** The canister calls `ic0.trap(...)` or `ic_cdk::trap(...)`.
//!   - **Wasm `unreachable`:** Rust's `panic!`/`unwrap()`/`expect()` compile to
//!     `unreachable` after printing the panic message via `ic0.trap`.
//!   - **Implicit wasm traps:** Integer divide-by-zero, integer overflow on `i32.trunc_f64_s`,
//!     out-of-bounds memory access, out-of-bounds table access, indirect call type mismatch,
//!     and stack overflow all cause the wasm runtime to trap immediately.
//!   - **System API traps:** Many `ic0.*` calls can trap on invalid arguments (e.g.,
//!     `ic0.msg_reply` called twice, `ic0.canister_cycle_balance` in the wrong context,
//!     `ic0.stable_read` with out-of-bounds offset). The system call never returns and the
//!     wasm execution is aborted.
//!   - **Instruction limit exceeded:** The IC halts execution when the per-message instruction
//!     limit is reached, which behaves identically to a trap.
//!
//!   In all of these cases the wrapper never executes, so the instruction count is 0. These
//!   inputs are still captured by `CrashFeedback` / `TimeoutFeedback` and saved as crashes
//!   or timeouts.
//!
//! - **The AFL overhead discount is approximate.** It assumes fixed IC instruction costs per
//!   wasm opcode (1 per opcode, 5 for `call`, 200 for `ic0.performance_counter` system API
//!   overhead). The IC's actual cost model may differ slightly. For fuzzing guidance (relative
//!   ordering of inputs), approximate is sufficient.
//!
//! - **`performance_counter(1)` includes inter-canister call instructions.** If the target
//!   method makes downstream calls, the counter includes instructions executed in callbacks.
//!   This is generally desirable (total cost of the message), but means the count is not
//!   purely the target canister's own instructions.

use anyhow::Result;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use wirm::ir::function::FunctionBuilder;
use wirm::ir::id::{FunctionID, GlobalID, LocalID, MemoryID};
use wirm::ir::module::module_functions::FuncKind;
use wirm::ir::types::{InitExpr, Instructions, Value};
use wirm::module_builder::AddLocal;
use wirm::opcode::Inject;
use wirm::wasmparser::{ExternalKind, MemArg, Operator, Validator};
use wirm::{DataType, InitInstr, Module, Opcode};

use crate::constants::{
    AFL_COVERAGE_MAP_SIZE, API_VERSION_IC0, COVERAGE_FN_EXPORT_NAME,
    INSTRUCTION_COUNT_FN_EXPORT_NAME,
};
use std::collections::HashSet;

/// Arguments for configuring the Wasm instrumentation process.
pub struct InstrumentationArgs {
    /// The raw Wasm module to instrument.
    pub wasm_bytes: Vec<u8>,
    /// The number of previous locations to track (must be 1, 2, 4, or 8).
    pub history_size: usize,
    /// The seed to use for instrumentation.
    pub seed: Seed,
    /// Whether to instrument canister_update/canister_query methods to track instruction counts.
    /// When enabled, wrapper functions are injected that read the IC performance counter
    /// after each method execution and an export function is added to retrieve the count.
    pub instrument_instruction_count: bool,
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
/// 1. Resolves all required `ic0` imports upfront (before adding local functions).
/// 2. Injects global variables required for tracking coverage.
/// 3. Injects the [`COVERAGE_FN_EXPORT_NAME`] update function to expose the coverage map.
/// 4. Instruments all functions by inserting calls to a helper function at the
///    start of each function and before each branch instruction.
///
/// When [`InstrumentationArgs::instrument_instruction_count`] is enabled, it additionally:
/// 5. Imports `ic0.performance_counter` and injects instruction-counting globals.
/// 6. Wraps each `canister_update` / `canister_query` export to read the instruction counter.
/// 7. Injects the [`INSTRUCTION_COUNT_FN_EXPORT_NAME`] export to retrieve the count.
fn instrument_for_afl(
    module: &mut Module<'_>,
    instrumentation_args: &InstrumentationArgs,
) -> Result<()> {
    let is_memory64 = is_memory64(module);
    let inst_count = instrumentation_args.instrument_instruction_count;

    // Ensure all ic0 imports upfront, before adding any local functions.
    // This is important because wirm's get_func returns import-list position,
    // which only matches the FunctionID before local functions shift indices.
    let (msg_reply_data_append_idx, msg_reply_idx, perf_counter_idx) =
        ensure_ic0_imports(module, is_memory64, inst_count)?;

    let (afl_prev_loc_indices, afl_mem_ptr_idx, instruction_count_globals) = inject_globals(
        module,
        instrumentation_args.history_size,
        is_memory64,
        inst_count,
    );
    println!(
        "  -> Injected globals: prev_locs @ indices {afl_prev_loc_indices:?}, mem_ptr @ index {afl_mem_ptr_idx:?}"
    );

    inject_afl_coverage_export(
        module,
        instrumentation_args.history_size,
        afl_mem_ptr_idx,
        msg_reply_data_append_idx,
        msg_reply_idx,
        is_memory64,
    )?;
    println!("  -> Injected `canister_update __export_coverage_for_afl` function.");

    // Instruction count wrapper functions (injected before branch instrumentation)
    let mut skip_function_ids = HashSet::new();

    let call_count_global = if let Some((ic_global, call_count_global)) = instruction_count_globals
    {
        let perf_counter_idx = perf_counter_idx.unwrap();
        println!(
            "  -> Injected instruction count globals: ic @ {ic_global:?}, call_count @ {call_count_global:?}"
        );
        println!("  -> Ensured ic0.performance_counter import @ {perf_counter_idx:?}");

        let cost_per_afl_call = compute_cost_per_afl_call(instrumentation_args.history_size);
        println!("  -> Computed AFL instrumentation cost per call: {cost_per_afl_call}");

        let wrapper_ids = inject_method_wrappers(
            module,
            call_count_global,
            ic_global,
            perf_counter_idx,
            cost_per_afl_call,
        );
        for id in &wrapper_ids {
            skip_function_ids.insert(*id);
        }
        println!(
            "  -> Injected {} method wrapper(s) for instruction counting.",
            wrapper_ids.len()
        );

        let export_fn_id = inject_instruction_count_export(
            module,
            instrumentation_args.history_size,
            afl_mem_ptr_idx,
            ic_global,
            msg_reply_data_append_idx,
            msg_reply_idx,
            is_memory64,
        )?;
        skip_function_ids.insert(export_fn_id);
        println!("  -> Injected `canister_query {INSTRUCTION_COUNT_FN_EXPORT_NAME}` function.");

        Some(call_count_global)
    } else {
        None
    };

    instrument_branches(
        module,
        &afl_prev_loc_indices,
        afl_mem_ptr_idx,
        instrumentation_args.seed,
        is_memory64,
        &skip_function_ids,
        call_count_global,
    );
    println!("  -> Instrumented branch instructions in all functions.");

    Ok(())
}

/// Injects the necessary global variables for AFL instrumentation.
///
/// **Always injected:**
/// - `__afl_prev_loc_N`: A set of `history_size` mutable i32 (or i64 for wasm64) globals to store the IDs
///   of the previously executed basic blocks.
/// - `__afl_mem_ptr`: An immutable i32 (or i64 for wasm64) global that holds the base address (0) of the coverage map.
///
/// **When `instrument_instruction_count` is true, also injects:**
/// - `__afl_instruction_count`: mutable i64 global storing the instruction count after method execution.
/// - `__afl_instrumentation_call_count`: mutable i64 global counting AFL helper function invocations per execution.
fn inject_globals(
    module: &mut Module<'_>,
    history_size: usize,
    is_memory64: bool,
    instrument_instruction_count: bool,
) -> (Vec<GlobalID>, GlobalID, Option<(GlobalID, GlobalID)>) {
    let mut afl_prev_loc_indices = Vec::with_capacity(history_size);

    let (ptr_type, init_val) = if is_memory64 {
        (DataType::I64, Value::I64(0))
    } else {
        (DataType::I32, Value::I32(0))
    };

    for _ in 0..history_size {
        let global_id = module.add_global(
            InitExpr::new(vec![InitInstr::Value(init_val)]),
            ptr_type,
            true,
            false,
        );
        afl_prev_loc_indices.push(global_id);
    }
    let afl_mem_ptr_idx = module.add_global(
        InitExpr::new(vec![InitInstr::Value(init_val)]),
        ptr_type,
        false,
        false,
    );

    let instruction_count_globals = if instrument_instruction_count {
        let instruction_count_global = module.add_global(
            InitExpr::new(vec![InitInstr::Value(Value::I64(0))]),
            DataType::I64,
            true,
            false,
        );
        let call_count_global = module.add_global(
            InitExpr::new(vec![InitInstr::Value(Value::I64(0))]),
            DataType::I64,
            true,
            false,
        );
        Some((instruction_count_global, call_count_global))
    } else {
        None
    };

    (
        afl_prev_loc_indices,
        afl_mem_ptr_idx,
        instruction_count_globals,
    )
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
    msg_reply_data_append_idx: FunctionID,
    msg_reply_idx: FunctionID,
    is_memory64: bool,
) -> Result<()> {
    let mut func_builder = FunctionBuilder::new(&[], &[]);

    if is_memory64 {
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i64_const(AFL_COVERAGE_MAP_SIZE as i64 * history_size as i64)
            .call(msg_reply_data_append_idx)
            .call(msg_reply_idx)
            .global_get(afl_mem_ptr_idx)
            .i32_const(0)
            .i64_const(AFL_COVERAGE_MAP_SIZE as i64 * history_size as i64)
            .memory_fill(0);
    } else {
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i32_const(AFL_COVERAGE_MAP_SIZE * history_size as i32)
            .call(msg_reply_data_append_idx)
            .call(msg_reply_idx)
            .global_get(afl_mem_ptr_idx)
            .i32_const(0)
            .i32_const(AFL_COVERAGE_MAP_SIZE * history_size as i32)
            .memory_fill(0);
    }

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
    is_memory64: bool,
    skip_function_ids: &HashSet<FunctionID>,
    call_count_global: Option<GlobalID>,
) {
    let instrumentation_function = afl_instrumentation_slice(
        module,
        afl_prev_loc_indices,
        afl_mem_ptr_idx,
        is_memory64,
        call_count_global,
    );

    let seed = match seed {
        Seed::Random => rand::rng().next_u32(),
        Seed::Static(s) => s,
    };
    println!("The seed used for instrumentation is {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);

    let mut create_instrumentation_ops = |ops: &mut Vec<Operator>| {
        let curr_location =
            rng.random_range(0..AFL_COVERAGE_MAP_SIZE * afl_prev_loc_indices.len() as i32);

        if is_memory64 {
            ops.push(Operator::I64Const {
                value: curr_location as i64,
            });
        } else {
            ops.push(Operator::I32Const {
                value: curr_location as i32,
            });
        }
        ops.push(Operator::Call {
            function_index: instrumentation_function.0,
        });
    };

    for (function_index, function) in module.functions.iter_mut().enumerate() {
        let func_id = FunctionID(function_index as u32);
        if matches!(function.kind(), FuncKind::Local(_))
            && func_id != instrumentation_function
            && !skip_function_ids.contains(&func_id)
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
/// The generated function takes the current location (`curr_location`) as an i32 (or i64 for wasm64)
/// parameter and is added to the module.
///
/// # Returns
///
/// The `FunctionID` of the newly created helper function.
fn afl_instrumentation_slice(
    module: &mut Module<'_>,
    afl_prev_loc_indices: &[GlobalID],
    afl_mem_ptr_idx: GlobalID,
    is_memory64: bool,
    call_count_global: Option<GlobalID>,
) -> FunctionID {
    if is_memory64 {
        let mut func_builder = FunctionBuilder::new(&[DataType::I64], &[]);
        let curr_location = LocalID(0);
        let afl_local_idx = func_builder.add_local(DataType::I64);

        func_builder.local_get(curr_location);
        for &prev_loc_idx in afl_prev_loc_indices {
            func_builder.global_get(prev_loc_idx).i64_xor();
        }

        func_builder
            .global_get(afl_mem_ptr_idx)
            .i64_add()
            .local_tee(afl_local_idx)
            .local_get(afl_local_idx)
            .i64_load8_u(MemArg {
                offset: 0,
                align: 0,
                memory: 0,
                max_align: 0,
            })
            .i64_const(1)
            .i64_add();

        // i64_store8 opcode trait doesn't exist
        func_builder.inject(Operator::I64Store8 {
            memarg: MemArg {
                offset: 0,
                align: 0,
                memory: 0,
                max_align: 0,
            },
        });

        // Shift the history
        for i in (1..afl_prev_loc_indices.len()).rev() {
            func_builder
                .global_get(afl_prev_loc_indices[i - 1])
                .i64_const(1)
                .i64_shr_unsigned()
                .global_set(afl_prev_loc_indices[i]);
        }

        func_builder
            .local_get(curr_location)
            .i64_const(1)
            .i64_shr_unsigned()
            .global_set(afl_prev_loc_indices[0]);

        // Increment AFL call counter if instruction counting is enabled
        if let Some(call_count_idx) = call_count_global {
            func_builder
                .global_get(call_count_idx)
                .i64_const(1)
                .i64_add()
                .global_set(call_count_idx);
        }

        func_builder.finish_module(module)
    } else {
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

        // Increment AFL call counter if instruction counting is enabled
        if let Some(call_count_idx) = call_count_global {
            func_builder
                .global_get(call_count_idx)
                .i64_const(1)
                .i64_add()
                .global_set(call_count_idx);
        }

        func_builder.finish_module(module)
    }
}

/// Computes the estimated IC instruction cost per AFL instrumentation call site.
///
/// Each instrumentation point consists of a **call site** (inlined at the branch)
/// and the **helper function body** (called from the site). The total cost is the
/// sum of both, assuming IC instruction cost = 1 per wasm opcode except `call` = 5.
///
/// ## Call site (2 wasm instructions, IC cost = 6)
///
/// ```text
/// i32/i64.const <random>   ;; cost 1
/// call $afl_helper          ;; cost 5
/// ```
///
/// ## Helper function body (IC cost = 13 + 6N, where N = history_size)
///
/// ```text
/// ;; XOR block: compute coverage map key          (1 + 2N instructions)
/// local.get(curr_location)                        ;; 1
/// N × (global.get(prev_loc[i]) + i32/i64.xor)    ;; 2N
///
/// ;; Address computation + load-increment-store   (8 instructions)
/// global.get(mem_ptr)                             ;; 1
/// i32/i64.add                                     ;; 1
/// local.tee(afl_local)                            ;; 1
/// local.get(afl_local)                            ;; 1
/// i32/i64.load8_u                                 ;; 1
/// i32/i64.const(1)                                ;; 1
/// i32/i64.add                                     ;; 1
/// i32/i64.store8                                  ;; 1
///
/// ;; History shift                                (4N instructions)
/// (N-1) × (global.get + const(1) + shr_u + global.set)  ;; 4(N-1)
/// local.get + const(1) + shr_u + global.set              ;; 4
///
/// ;; Call counter increment (only when instruction counting is enabled, +4)
/// global.get(call_count) + i64.const(1) + i64.add + global.set(call_count)
/// ```
///
/// ## Total per instrumentation point
///
/// `6 + 13 + 6N + 4 = 23 + 6N` (IC instructions, approximate)
///
/// The wasm32 and wasm64 code paths produce the same number of wasm instructions
/// (just using i32 vs i64 variants), so the instruction count is `23 + 6N` for both.
///
/// Note: the IC applies a `WASM64_INSTRUCTION_COST_OVERHEAD` multiplier (currently 2×)
/// when **charging cycles** for wasm64 execution (see `rs/config/src/subnet_config.rs`
/// in `dfinity/ic`), but this only affects the cycle fee — it does NOT affect
/// `ic0.performance_counter`, which reports the raw instruction count without any
/// multiplier. Therefore the overhead formula is the same for wasm32 and wasm64.
///
/// This is an approximation — the IC's actual cost model may assign different
/// weights to some opcodes. For fuzzing guidance (relative ordering of inputs),
/// an approximate discount is sufficient.
fn compute_cost_per_afl_call(history_size: usize) -> i64 {
    let n = history_size as i64;
    // call site (6) + body (13 + 6N) + call counter increment (4)
    23 + 6 * n
}

/// Fixed IC instruction cost of the wrapper function itself, up to and including the
/// `call ic0.performance_counter` that reads the counter. These instructions are counted
/// by performance_counter but are not part of the original canister method or AFL
/// instrumentation, so they must be subtracted separately.
///
/// System API calls have an additional overhead beyond the wasm `call` opcode cost.
/// The overhead is charged via `charge_for_cpu()` *before* the counter is read, so the
/// value returned by `performance_counter` already includes it. See
/// `rs/embedders/src/wasmtime_embedder/system_api_complexity.rs` in the IC repo for
/// the full list of overhead constants.
///
/// ```text
/// i64.const(0)          ;; 1     — reset call counter
/// global.set            ;; 1
/// call original_method  ;; 5     — call opcode (local function, no system API overhead)
/// i32.const(1)          ;; 1     — perf counter type arg
/// call perf_counter     ;; 205   — call opcode (5) + system API overhead (200)
/// Total                 = 213Th
/// ```
const WRAPPER_OVERHEAD_COST: i64 = 213;

/// Injects wrapper functions around canister_update and canister_query exports.
///
/// Each wrapper resets the AFL call counter, calls the original method, reads the
/// performance counter, subtracts estimated AFL overhead and its own fixed overhead,
/// and stores the result.
fn inject_method_wrappers(
    module: &mut Module<'_>,
    call_count_global: GlobalID,
    instruction_count_global: GlobalID,
    perf_counter_idx: FunctionID,
    cost_per_afl_call: i64,
) -> Vec<FunctionID> {
    // Collect exports to wrap: (export_index, original_function_id, export_name)
    let exports_to_wrap: Vec<(usize, FunctionID)> = module
        .exports
        .iter()
        .enumerate()
        .filter(|(_, exp)| {
            matches!(exp.kind, ExternalKind::Func)
                && (exp.name.starts_with("canister_update ")
                    || exp.name.starts_with("canister_query "))
                && !exp.name.contains(COVERAGE_FN_EXPORT_NAME)
                && !exp.name.contains(INSTRUCTION_COUNT_FN_EXPORT_NAME)
        })
        .map(|(idx, exp)| (idx, FunctionID(exp.index)))
        .collect();

    let mut wrapper_ids = Vec::new();

    for (export_idx, original_func_id) in exports_to_wrap {
        let mut func_builder = FunctionBuilder::new(&[], &[]);

        // Reset AFL call counter
        func_builder.i64_const(0).global_set(call_count_global);

        // Call the original method
        func_builder.call(original_func_id);

        // Read instruction counter (type=1: call context counter)
        func_builder.i32_const(1).call(perf_counter_idx);

        // Subtract AFL instrumentation overhead: call_count * cost_per_call
        func_builder
            .global_get(call_count_global)
            .i64_const(cost_per_afl_call)
            .i64_mul()
            .i64_sub();

        // Subtract the fixed overhead of this wrapper itself (instructions counted
        // before performance_counter returns)
        func_builder.i64_const(WRAPPER_OVERHEAD_COST).i64_sub();

        // Store result
        func_builder.global_set(instruction_count_global);

        let wrapper_id = func_builder.finish_module(module);
        wrapper_ids.push(wrapper_id);

        // Re-point the export to the wrapper
        // We need to get a mutable reference to the export and change its index
        for (idx, exp) in module.exports.iter_mut().enumerate() {
            if idx == export_idx {
                exp.index = *wrapper_id;
                break;
            }
        }
    }

    wrapper_ids
}

/// Injects the `canister_query __export_instruction_count_for_afl` function.
///
/// Exported as a query because it only reads the `__afl_instruction_count` global
/// (set during the preceding update call) and does not modify persistent state.
/// The scratch memory write is transient and discarded after the query returns.
fn inject_instruction_count_export<'a>(
    module: &mut Module<'a>,
    history_size: usize,
    afl_mem_ptr_idx: GlobalID,
    instruction_count_global: GlobalID,
    msg_reply_data_append_idx: FunctionID,
    msg_reply_idx: FunctionID,
    is_memory64: bool,
) -> Result<FunctionID> {
    let scratch_offset = AFL_COVERAGE_MAP_SIZE as i64 * history_size as i64;

    let mut func_builder = FunctionBuilder::new(&[], &[]);

    if is_memory64 {
        // Store instruction count to scratch memory
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i64_const(scratch_offset)
            .i64_add();
        func_builder
            .global_get(instruction_count_global)
            .i64_store(MemArg {
                offset: 0,
                align: 3, // 2^3 = 8 byte alignment for i64
                memory: 0,
                max_align: 0,
            });

        // Reply with 8 bytes from scratch offset
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i64_const(scratch_offset)
            .i64_add()
            .i64_const(8)
            .call(msg_reply_data_append_idx)
            .call(msg_reply_idx);
    } else {
        // Store instruction count to scratch memory
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i32_const(scratch_offset as i32)
            .i32_add();
        func_builder
            .global_get(instruction_count_global)
            .i64_store(MemArg {
                offset: 0,
                align: 3,
                memory: 0,
                max_align: 0,
            });

        // Reply with 8 bytes from scratch offset
        func_builder
            .global_get(afl_mem_ptr_idx)
            .i32_const(scratch_offset as i32)
            .i32_add()
            .i32_const(8)
            .call(msg_reply_data_append_idx)
            .call(msg_reply_idx);
    }

    let function_id = func_builder.finish_module(module);
    let export_name = format!("canister_query {INSTRUCTION_COUNT_FN_EXPORT_NAME}");
    module.exports.add_export_func(export_name, function_id.0);

    Ok(function_id)
}

/// Ensures that the necessary `ic0` System API functions are imported.
///
/// **Always imported:**
/// - `ic0.msg_reply_data_append` — needed by the coverage export function.
/// - `ic0.msg_reply` — needed by the coverage export function.
///
/// **When `instrument_instruction_count` is true, also imports:**
/// - `ic0.performance_counter : (i32) -> (i64)` — needed by method wrappers.
///
/// All imports must be resolved upfront before adding any local functions, because
/// wirm's `get_func` returns import-list positions that only match function-space IDs
/// before local functions shift indices.
fn ensure_ic0_imports(
    module: &mut Module<'_>,
    is_memory64: bool,
    instrument_instruction_count: bool,
) -> Result<(FunctionID, FunctionID, Option<FunctionID>)> {
    let mut data_append_idx = module.imports.get_func(
        API_VERSION_IC0.to_string(),
        "msg_reply_data_append".to_string(),
    );
    let mut reply_idx = module
        .imports
        .get_func(API_VERSION_IC0.to_string(), "msg_reply".to_string());

    if data_append_idx.is_none() {
        let ptr_type = if is_memory64 {
            DataType::I64
        } else {
            DataType::I32
        };
        let type_id = module.types.add_func_type(&[ptr_type, ptr_type], &[]);
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

    let perf_counter_idx = if instrument_instruction_count {
        let existing = module.imports.get_func(
            API_VERSION_IC0.to_string(),
            "performance_counter".to_string(),
        );
        if let Some(idx) = existing {
            Some(idx)
        } else {
            let type_id = module
                .types
                .add_func_type(&[DataType::I32], &[DataType::I64]);
            let (func_index, _) = module.add_import_func(
                API_VERSION_IC0.to_string(),
                "performance_counter".to_string(),
                type_id,
            );
            Some(func_index)
        }
    } else {
        None
    };

    Ok((
        data_append_idx.unwrap(),
        reply_idx.unwrap(),
        perf_counter_idx,
    ))
}

/// Checks if the module is using 64-bit memory addressing for the purpose of instrumentation.
///
/// This function determines whether to use 64-bit or 32-bit instructions for memory operations
/// and global variables injected during instrumentation.
///
/// The logic is as follows:
/// 1. If the module's memory (index 0) is 32-bit, it returns `false`.
/// 2. If the memory is 64-bit:
///    - If `ic0.msg_reply_data_append` is NOT imported, it assumes 64-bit usage and returns `true`.
///    - If `ic0.msg_reply_data_append` IS imported, it checks the function signature.
///      - If the parameters are `i64`, it returns `true`.
///      - Otherwise (e.g., `i32`), it returns `false`.
fn is_memory64(module: &Module<'_>) -> bool {
    let memory_64 = module
        .memories
        .get_mem_by_id(MemoryID(0))
        .map(|m| m.ty.memory64)
        .unwrap_or(false);

    // The module is wasm32, no further checks needed
    if !memory_64 {
        return false;
    }

    // The module is guaranteed to be wasm64
    let data_append_idx = module.imports.get_func(
        API_VERSION_IC0.to_string(),
        "msg_reply_data_append".to_string(),
    );

    // If the systemAPI is not imported, we can safely choose i64 for wasm64
    if data_append_idx.is_none() {
        return true;
    }

    // If the systemAPI is imported, we follow the imported DataType for compatability
    // See: https://legacy.internetcomputer.org/docs/references/ic-interface-spec#responding
    let type_id = module
        .functions
        .get_fn_by_id(data_append_idx.unwrap())
        .unwrap()
        .get_type_id();
    let ty = module.types.get(type_id).unwrap();
    ty.params().iter().all(|v| matches!(v, DataType::I64))
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
            let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
                inject_globals(&mut module, history_size, false, false);

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
            let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
                inject_globals(&mut module, history_size, false, false);

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
            let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
                inject_globals(&mut module, history_size, false, false);

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
        let (data_append_idx, reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();

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
        let (data_append_idx, reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();

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
        let (data_append_idx, reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();

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
        let (data_append_idx, reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();

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
        let (data_append_idx, reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();

        assert_eq!(data_append_idx, FunctionID(0));
        assert_eq!(reply_idx, FunctionID(1));
    }

    /// Helper function to test equality between two generated Wasm modules
    /// If they are not equal, it displays the textual difference of the WAT.
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
    fn inject_instrumentation_function_history_1() {
        let wat = wat::parse_str(
            r#"
                (module
                    (memory (;0;) 1)
                )
            "#,
        )
        .unwrap();

        let history_size = 1;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
            inject_globals(&mut module, history_size, false, false);
        let instrumentation_function = afl_instrumentation_slice(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            false,
            None,
        );
        assert_eq!(instrumentation_function, FunctionID(0));
        let expected_wasm = wat::parse_str(
            r#"(module
                            (type (;0;) (func (param i32)))
                            (memory (;0;) 1)
                            (global (;0;) (mut i32) i32.const 0)
                            (global (;1;) i32 i32.const 0)
                            (func (;0;) (type 0) (param i32)
                                (local i32)
                                local.get 0
                                global.get 0
                                i32.xor
                                global.get 1
                                i32.add
                                local.tee 1
                                local.get 1
                                i32.load8_u
                                i32.const 1
                                i32.add
                                i32.store8
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
    fn inject_instrumentation_function_history_2() {
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
        let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
            inject_globals(&mut module, history_size, false, false);
        let instrumentation_function = afl_instrumentation_slice(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            false,
            None,
        );
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
    fn inject_afl_coverage_export_history_1() {
        let wat = wat::parse_str(
            r#"
                (module
                    (memory (;0;) 1)
                )
            "#,
        )
        .unwrap();

        let history_size = 1;
        let mut module = Module::parse(&wat, false, false).unwrap();
        let (msg_reply_data_append_idx, msg_reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();
        let (_, afl_mem_ptr_idx, _) = inject_globals(&mut module, history_size, false, false);
        let coverage_function = inject_afl_coverage_export(
            &mut module,
            history_size,
            afl_mem_ptr_idx,
            msg_reply_data_append_idx,
            msg_reply_idx,
            false,
        );
        assert!(coverage_function.is_ok());
        let expected_wasm = wat::parse_str(
            r#"(module
                    (type (;0;) (func (param i32 i32)))
                    (type (;1;) (func))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 0)))
                    (import "ic0" "msg_reply" (func (;1;) (type 1)))
                    (memory (;0;) 1)
                    (global (;0;) (mut i32) i32.const 0)
                    (global (;1;) i32 i32.const 0)
                    (export "canister_update __export_coverage_for_afl" (func 2))
                    (func (;2;) (type 1)
                        global.get 1
                        i32.const 65536
                        call 0
                        call 1
                        global.get 1
                        i32.const 0
                        i32.const 65536
                        memory.fill
                    )
                )"#,
        )
        .unwrap();
        let mut expected_module = Module::parse(&expected_wasm, false, false).unwrap();
        wasm_equality(module.encode(), expected_module.encode());
    }

    #[test]
    fn inject_afl_coverage_export_history_2() {
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
        let (msg_reply_data_append_idx, msg_reply_idx, _) =
            ensure_ic0_imports(&mut module, false, false).unwrap();
        let (_, afl_mem_ptr_idx, _) = inject_globals(&mut module, history_size, false, false);
        let coverage_function = inject_afl_coverage_export(
            &mut module,
            history_size,
            afl_mem_ptr_idx,
            msg_reply_data_append_idx,
            msg_reply_idx,
            false,
        );
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
        let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
            inject_globals(&mut module, history_size, false, false);
        instrument_branches(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            Seed::Static(42),
            false,
            &HashSet::new(),
            None,
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
    fn inject_branch_instrumentation_func() {
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
    fn inject_branch_instrumentation_block() {
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
    fn inject_branch_instrumentation_loop() {
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
    fn inject_branch_instrumentation_if() {
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
    fn inject_branch_instrumentation_if_else() {
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
    fn inject_branch_instrumentation_br() {
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
    fn inject_branch_instrumentation_brif() {
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
    fn inject_branch_instrumentation_return() {
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
    fn inject_branch_instrumentation_brtable() {
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
        let (afl_prev_loc_indices, afl_mem_ptr_idx, _) =
            inject_globals(&mut module, history_size, false, false);
        instrument_branches(
            &mut module,
            &afl_prev_loc_indices,
            afl_mem_ptr_idx,
            Seed::Static(42),
            false,
            &HashSet::new(),
            None,
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

    #[should_panic]
    #[test]
    fn instrumentation_panic_history_size_3() {
        let wat = wat::parse_str(
            r#"
                (module)
            "#,
        )
        .unwrap();

        let history_size: usize = 3;

        let _ = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: wat,
            history_size,
            seed: Seed::Random,
            instrument_instruction_count: false,
        });
    }

    #[test]
    fn instrumentation_round_trip() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i32)))
                    (memory (;0;) 1)
                    (export "memory" (memory 0))
                    (export "check_even" (func 0))
                    (func (;0;) (type 0) (param $num i32)
                        local.get $num
                        i32.const 2
                        i32.rem_u
                        i32.eqz
                        if ;; label = @1
                        i32.const 0
                        i32.const 1
                        i32.store
                        else
                        i32.const 0
                        i32.const 0
                        i32.store
                        end
                    )
                )
            "#,
        )
        .unwrap();

        let history_size: usize = 2;

        let expected = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i32)))
                    (type (;1;) (func (param i32 i32)))
                    (type (;2;) (func))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 1)))
                    (import "ic0" "msg_reply" (func (;1;) (type 2)))
                    (memory (;0;) 1)
                    (global (;0;) (mut i32) i32.const 0)
                    (global (;1;) (mut i32) i32.const 0)
                    (global (;2;) i32 i32.const 0)
                    (export "memory" (memory 0))
                    (export "check_even" (func 2))
                    (export "canister_update __export_coverage_for_afl" (func 3))
                    (func (;2;) (type 0) (param i32)
                        i32.const 17486
                        call 4
                        local.get 0
                        i32.const 2
                        i32.rem_u
                        i32.eqz
                        if ;; label = @1
                        i32.const 69016
                        call 4
                        i32.const 0
                        i32.const 1
                        i32.store
                        else
                        i32.const 32602
                        call 4
                        i32.const 0
                        i32.const 0
                        i32.store
                        end
                    )
                    (func (;3;) (type 2)
                        i32.const 71136
                        call 4
                        global.get 2
                        i32.const 131072
                        call 0
                        call 1
                        global.get 2
                        i32.const 0
                        i32.const 131072
                        memory.fill
                    )
                    (func (;4;) (type 0) (param i32)
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
                    )
            "#,
        )
        .unwrap();

        let generated = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: wat,
            history_size,
            seed: Seed::Static(42),
            instrument_instruction_count: false,
        });

        wasm_equality(generated, expected);
    }

    #[test]
    fn instrumentation_round_trip_wasm64() {
        let wat = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i64)))
                    (memory (;0;) i64 1)
                    (export "memory" (memory 0))
                    (export "check_even" (func 0))
                    (func (;0;) (type 0) (param $num i64)
                        local.get $num
                        i64.const 2
                        i64.rem_u
                        i64.eqz
                        if ;; label = @1
                        i64.const 0
                        i64.const 1
                        i64.store
                        else
                        i64.const 0
                        i64.const 0
                        i64.store
                        end
                    )
                )
            "#,
        )
        .unwrap();

        let history_size: usize = 2;

        let expected = wat::parse_str(
            r#"
                (module
                    (type (;0;) (func (param i64)))
                    (type (;1;) (func (param i64 i64)))
                    (type (;2;) (func))
                    (import "ic0" "msg_reply_data_append" (func (;0;) (type 1)))
                    (import "ic0" "msg_reply" (func (;1;) (type 2)))
                    (memory (;0;) i64 1)
                    (global (;0;) (mut i64) i64.const 0)
                    (global (;1;) (mut i64) i64.const 0)
                    (global (;2;) i64 i64.const 0)
                    (export "memory" (memory 0))
                    (export "check_even" (func 2))
                    (export "canister_update __export_coverage_for_afl" (func 3))
                    (func (;2;) (type 0) (param i64)
                        i64.const 17486
                        call 4
                        local.get 0
                        i64.const 2
                        i64.rem_u
                        i64.eqz
                        if ;; label = @1
                        i64.const 69016
                        call 4
                        i64.const 0
                        i64.const 1
                        i64.store
                        else
                        i64.const 32602
                        call 4
                        i64.const 0
                        i64.const 0
                        i64.store
                        end
                    )
                    (func (;3;) (type 2)
                        i64.const 71136
                        call 4
                        global.get 2
                        i64.const 131072
                        call 0
                        call 1
                        global.get 2
                        i32.const 0
                        i64.const 131072
                        memory.fill
                    )
                    (func (;4;) (type 0) (param i64)
                        (local i64)
                        local.get 0
                        global.get 0
                        i64.xor
                        global.get 1
                        i64.xor
                        global.get 2
                        i64.add
                        local.tee 1
                        local.get 1
                        i64.load8_u
                        i64.const 1
                        i64.add
                        i64.store8
                        global.get 0
                        i64.const 1
                        i64.shr_u
                        global.set 1
                        local.get 0
                        i64.const 1
                        i64.shr_u
                        global.set 0
                    )
                    )
            "#,
        )
        .unwrap();

        let generated = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: wat,
            history_size,
            seed: Seed::Static(42),
            instrument_instruction_count: false,
        });

        wasm_equality(generated, expected);
    }

    #[test]
    fn test_is_memory64_wasm32() {
        let wat = wat::parse_str(r#"(module (memory 1))"#).unwrap();
        let module = Module::parse(&wat, false, false).unwrap();
        assert!(!is_memory64(&module));
    }

    #[test]
    fn test_is_memory64_wasm64_no_import() {
        let wat = wat::parse_str(r#"(module (memory i64 1))"#).unwrap();
        let module = Module::parse(&wat, false, false).unwrap();
        assert!(is_memory64(&module));
    }

    #[test]
    fn test_is_memory64_wasm64_import_i64() {
        let wat = wat::parse_str(
            r#"
            (module
                (import "ic0" "msg_reply_data_append" (func (param i64 i64)))
                (memory i64 1)
            )
            "#,
        )
        .unwrap();
        let module = Module::parse(&wat, false, false).unwrap();
        assert!(is_memory64(&module));
    }

    #[test]
    fn test_is_memory64_wasm64_import_i32() {
        let wat = wat::parse_str(
            r#"
            (module
                (import "ic0" "msg_reply_data_append" (func (param i32 i32)))
                (memory i64 1)
            )
            "#,
        )
        .unwrap();
        let module = Module::parse(&wat, false, false).unwrap();
        assert!(!is_memory64(&module));
    }

    #[test]
    fn instruction_count_instrumentation_wasm32() {
        // A module with a canister_update export — should get a wrapper and instruction count export
        let wat = wat::parse_str(
            r#"
            (module
                (type (;0;) (func))
                (import "ic0" "msg_reply" (func (;0;) (type 0)))
                (memory (;0;) 1)
                (export "memory" (memory 0))
                (export "canister_update my_method" (func 1))
                (func (;1;) (type 0)
                    call 0
                )
            )
            "#,
        )
        .unwrap();

        let generated = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: wat,
            history_size: 1,
            seed: Seed::Static(42),
            instrument_instruction_count: true,
        });

        // Verify the instrumented module is valid
        validate_wasm(&generated).unwrap();

        // Parse the generated module and check for expected exports
        let module = Module::parse(&generated, false, false).unwrap();

        // Should have the original export, coverage export, and instruction count export
        let has_coverage_export = module
            .exports
            .get_by_name(format!("canister_update {COVERAGE_FN_EXPORT_NAME}"))
            .is_some();
        let has_instruction_export = module
            .exports
            .get_by_name(format!("canister_query {INSTRUCTION_COUNT_FN_EXPORT_NAME}"))
            .is_some();
        let has_original_export = module
            .exports
            .get_by_name("canister_update my_method".to_string())
            .is_some();

        assert!(has_coverage_export, "Missing coverage export");
        assert!(has_instruction_export, "Missing instruction count export");
        assert!(has_original_export, "Missing original method export");

        // The original export should now point to a different function (the wrapper)
        let original_func_id = module
            .exports
            .get_func_by_name("canister_update my_method".to_string())
            .unwrap();
        // Original function was func 1 (after import at 0), wrapper should be a new function
        assert_ne!(
            original_func_id,
            FunctionID(1),
            "Export should point to wrapper, not original function"
        );

        // Check that performance_counter import exists
        let perf_counter = module
            .imports
            .get_func("ic0".to_string(), "performance_counter".to_string());
        assert!(perf_counter.is_some(), "Missing performance_counter import");
    }

    #[test]
    fn instruction_count_no_canister_exports() {
        // A module with no canister_update/query exports — should still work but no wrappers
        let wat = wat::parse_str(
            r#"
            (module
                (memory (;0;) 1)
                (export "memory" (memory 0))
                (func (;0;)
                    nop
                )
            )
            "#,
        )
        .unwrap();

        let generated = instrument_wasm_for_fuzzing(InstrumentationArgs {
            wasm_bytes: wat,
            history_size: 1,
            seed: Seed::Static(42),
            instrument_instruction_count: true,
        });

        validate_wasm(&generated).unwrap();

        let module = Module::parse(&generated, false, false).unwrap();

        // Should still have instruction count export even with no canister methods
        let has_instruction_export = module
            .exports
            .get_by_name(format!("canister_query {INSTRUCTION_COUNT_FN_EXPORT_NAME}"))
            .is_some();
        assert!(has_instruction_export, "Missing instruction count export");
    }

    #[test]
    fn compute_cost_per_afl_call_values() {
        // history_size=1: 23 + 6*1 = 29
        assert_eq!(compute_cost_per_afl_call(1), 29);
        // history_size=2: 23 + 6*2 = 35
        assert_eq!(compute_cost_per_afl_call(2), 35);
        // history_size=4: 23 + 6*4 = 47
        assert_eq!(compute_cost_per_afl_call(4), 47);
        // history_size=8: 23 + 6*8 = 71
        assert_eq!(compute_cost_per_afl_call(8), 71);
    }
}
