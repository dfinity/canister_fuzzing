//! Fuzzer that maximizes IC instructions consumed by Candid decoding.
//!
//! This example demonstrates **automated instruction counting** via wasm instrumentation.
//! The target canister (`decode_candid`) is instrumented with
//! `instrument_instruction_count: true`, which injects wrapper functions that read
//! `ic0.performance_counter` after each method call. No manual changes to the canister
//! source code are needed.
//!
//! The fuzzer overrides `instruction_config()` with `enabled: true` to enable the
//! [`InstructionCountFeedback`](canfuzz::custom::feedback::instruction_count::InstructionCountFeedback),
//! which considers inputs that increase the maximum instruction count as "interesting".

use candid::{Encode, Principal};
use canfuzz::define_fuzzer_state;
use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};
use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::{parse_canister_result_for_trap, read_canister_bytes};

use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::BytesInput;
use pocket_ic::PocketIcBuilder;
use slog::Level;
use std::path::PathBuf;
use std::time::Duration;

define_fuzzer_state!(DecodeCandidFuzzer);

fn main() {
    let canister = CanisterBuilder::new("decode_candid")
        .with_wasm_env("DECODE_CANDID_WASM_PATH")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("decode_candid_by_instructions")
        .with_canister(canister)
        .build();

    let mut fuzzer_state = DecodeCandidFuzzer(state);

    fuzzer_state.run();
}

impl FuzzerOrchestrator for DecodeCandidFuzzer {
    fn corpus_dir(&self) -> std::path::PathBuf {
        PathBuf::from(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("corpus")
    }

    fn init(&mut self) {
        let test = PocketIcBuilder::new()
            .with_application_subnet()
            .with_log_level(Level::Critical)
            .build();
        self.as_mut().init_state(test);
        let test = self.get_state_machine();

        for info in self.as_mut().get_iter_mut_canister_info() {
            let canister_id = test.create_canister();
            test.add_cycles(canister_id, u128::MAX / 2);
            let module = instrument_wasm_for_fuzzing(InstrumentationArgs {
                wasm_bytes: read_canister_bytes(info.wasm_path.clone()),
                history_size: 8,
                seed: Seed::Random,
                instrument_instruction_count: true,
            });
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    fn execute(&self, input: BytesInput) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let result = test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "decode",
            Encode!(&bytes).unwrap(),
        );

        let status = parse_canister_result_for_trap(result);
        // For candid decoding, explicit traps are common and not interesting, so we wrap them as OK
        let status = if status != ExitKind::Crash {
            status
        } else {
            ExitKind::Ok
        };

        test.advance_time(Duration::from_secs(60));

        status
    }

    fn instruction_config() -> canfuzz::orchestrator::InstructionConfig {
        canfuzz::orchestrator::InstructionConfig {
            enabled: true,
            debug: true,
        }
    }
}
