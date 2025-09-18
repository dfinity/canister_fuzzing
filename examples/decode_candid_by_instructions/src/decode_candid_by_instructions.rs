use canister_fuzzer::custom::decode_map::{DECODING_MAP_OBSERVER_NAME, DecodingMapFeedback, MAP};
use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canister_fuzzer::util::{parse_canister_result_for_trap, read_canister_bytes};

use candid::{Decode, Encode, Principal};
use canister_fuzzer::libafl::executors::ExitKind;
use canister_fuzzer::libafl::feedback_or;
use canister_fuzzer::libafl::inputs::ValueInput;
use canister_fuzzer::libafl::observers::RefCellValueObserver;
use canister_fuzzer::libafl::stages::{AflStatsStage, CalibrationStage};
use pocket_ic::PocketIcBuilder;
use slog::Level;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::ptr::addr_of;
use std::time::Duration;

use canister_fuzzer::libafl::{
    Evaluator,
    corpus::inmemory_ondisk::InMemoryOnDiskCorpus,
    events::SimpleEventManager,
    executors::inprocess::InProcessExecutor,
    feedbacks::{CrashFeedback, map::AflMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::{HavocScheduledMutator, havoc_mutations},
    observers::map::{StdMapObserver, hitcount_map::HitcountsMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use canister_fuzzer::libafl::monitors::SimpleMonitor;
// use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
use canister_fuzzer::libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};

fn main() {
    let mut fuzzer_state = DecodeCandidFuzzer(FuzzerState::new(
        "decode_candid_by_instructions",
        vec![CanisterInfo {
            id: None,
            name: "candid_decode".to_string(),
            wasm_path: WasmPath::EnvVar("DECODE_CANDID_WASM_PATH".to_string()),
            ty: CanisterType::Coverage,
        }],
    ));

    fuzzer_state.run();
}

struct DecodeCandidFuzzer(FuzzerState);

impl FuzzerStateProvider for DecodeCandidFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState {
        &self.0
    }
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
        self.0.init_state(test);
        let test = self.get_state_machine();

        for info in self.0.get_iter_mut_canister_info() {
            let canister_id = test.create_canister();
            test.add_cycles(canister_id, 5_000_000_000_000);
            let module =
                instrument_wasm_for_fuzzing(&read_canister_bytes(info.wasm_path.clone()), 4);
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    #[allow(static_mut_refs)]
    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let result = parse_canister_result_for_trap(test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "parse_candid",
            Encode!(&bytes).unwrap(),
        ));

        let instructions = if result.0 == ExitKind::Ok && result.1.is_some() {
            Decode!(&result.1.unwrap(), u64).unwrap()
        } else {
            0
        };

        test.advance_time(Duration::from_secs(1));
        test.tick();

        let ratio = instructions / bytes.len() as u64;
        let previous_ratio = unsafe { MAP.borrow().previous_ratio };
        let mut decoding_map = unsafe { MAP.borrow_mut() };
        if ratio > previous_ratio {
            decoding_map.increased = true;
            decoding_map.previous_ratio = ratio;
            println!("Current ratio {ratio:?}, previous ratio {previous_ratio:?}");
        } else {
            decoding_map.increased = false;
        }

        // The success condition for the fuzzer is cycles consumed to input length ratio is
        // over a certain threshold. Once we reach this condition, the fuzzer creates a crash.
        if ratio > 10_000_000 {
            return ExitKind::Crash;
        }
        ExitKind::Ok
    }

    fn run(&mut self) {
        self.init();

        let mut harness = |input: &BytesInput| {
            self.setup();
            let result = self.execute(input.clone());
            self.set_coverage_map();
            result
        };

        let decoding_map_observer = unsafe {
            RefCellValueObserver::new(
                DECODING_MAP_OBSERVER_NAME,
                canister_fuzzer::libafl_bolts::ownedref::OwnedRef::from_ptr(addr_of!(MAP)),
            )
        };

        let decoding_feedback = DecodingMapFeedback::new();
        let hitcount_map_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::new("coverage_map", self.get_coverage_map())
        });
        let afl_map_feedback = AflMapFeedback::new(&hitcount_map_observer);
        let calibration_stage = CalibrationStage::new(&afl_map_feedback);
        let mut feedback = feedback_or!(decoding_feedback, afl_map_feedback);
        let mut objective = CrashFeedback::new();

        let stats_stage = AflStatsStage::builder()
            .map_observer(&hitcount_map_observer)
            .build()
            .unwrap();

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::no_meta(self.input_dir()).unwrap(),
            InMemoryOnDiskCorpus::no_meta(self.crashes_dir()).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mon = SimpleMonitor::new(|s| println!("{s}"));

        // let ui = TuiUI::with_version(
        //     String::from("Decode Candid by Instruction / Input Ratio"),
        //     String::from("0.0.1"),
        //     false,
        // );
        // let mon = TuiMonitor::new(ui);

        let mut mgr = SimpleEventManager::new(mon);
        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(hitcount_map_observer, decoding_map_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create the Executor");

        // bazel run @candid//:didc random -- -d gateway.did -t '(HttpResponse)' | bazel run @candid//:didc encode | xxd -r -p
        let paths = fs::read_dir(self.corpus_dir()).unwrap();
        for path in paths {
            let p = path.unwrap().path();
            let mut f = File::open(p.clone()).unwrap();
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer).unwrap();
            fuzzer
                .evaluate_input(
                    &mut state,
                    &mut executor,
                    &mut mgr,
                    &BytesInput::new(buffer),
                )
                .unwrap();
        }

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(
            calibration_stage,
            StdMutationalStage::new(mutator),
            stats_stage
        );
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
