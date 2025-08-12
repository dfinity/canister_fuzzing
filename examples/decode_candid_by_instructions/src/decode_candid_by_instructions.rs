use canister_fuzzer::custom::decode_map::{DecodingMapFeedback, DECODING_MAP_OBSERVER_NAME, MAP};
use canister_fuzzer::fuzzer::{CanisterInfo, FuzzerState};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::FuzzerOrchestrator;
use canister_fuzzer::sandbox_shim::sandbox_main;
use canister_fuzzer::util::read_canister_bytes;

use candid::{Decode, Encode};
use ic_state_machine_tests::{ErrorCode, StateMachineBuilder};
use ic_types::{ingress::WasmResult, Cycles};
use libafl::executors::ExitKind;
use libafl::feedback_or;
use libafl::inputs::ValueInput;
use libafl::observers::RefCellValueObserver;
use libafl::stages::{AflStatsStage, CalibrationStage};
use slog::Level;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::ptr::addr_of;
use std::time::Duration;

use libafl::{
    corpus::inmemory_ondisk::InMemoryOnDiskCorpus,
    events::SimpleEventManager,
    executors::inprocess::InProcessExecutor,
    feedbacks::{map::AflMapFeedback, CrashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::{havoc_mutations, HavocScheduledMutator},
    observers::map::{hitcount_map::HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Evaluator,
};

use libafl::monitors::SimpleMonitor;
// use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};

fn main() {
    let fuzzer_state = DecodeCandidFuzzer(FuzzerState {
        state: None,
        canisters: vec![CanisterInfo {
            id: None,
            name: "candid_decode".to_string(),
            env_var: "DECODE_CANDID_WASM_PATH".to_string(),
        }],
        fuzzer_dir: "examples/decode_candid_by_instructions".to_string(),
    });

    sandbox_main(run, fuzzer_state);
}

struct DecodeCandidFuzzer(FuzzerState);

impl FuzzerOrchestrator for DecodeCandidFuzzer {
    fn init(&mut self) {
        let test = StateMachineBuilder::new()
            .with_log_level(Some(Level::Critical))
            .build();
        let fuzzer_state = &mut self.0;
        fuzzer_state.state = Some(test);

        for info in fuzzer_state.canisters.iter_mut() {
            let module = instrument_wasm_for_fuzzing(&read_canister_bytes(&info.env_var));
            let canister_id = fuzzer_state
                .state
                .as_ref()
                .unwrap()
                .install_canister_with_cycles(module, vec![], None, Cycles::new(5_000_000_000_000))
                .unwrap();
            info.id = Some(canister_id);
        }
    }

    fn setup(&self) {}

    #[allow(static_mut_refs)]
    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();

        let bytes: Vec<u8> = input.into();
        let result = test.execute_ingress(
            fuzzer_state.get_canister_id_by_name("candid_decode"),
            "parse_candid",
            Encode!(&bytes).unwrap(),
        );
        let instructions = match result {
            Ok(WasmResult::Reply(result)) => {
                // let mut instructions = [0u8; 8];
                // instructions.clone_from_slice(&result[0..8]);
                // u64::from_le_bytes(instructions)
                Decode!(&result, u64).unwrap()
            }
            Ok(WasmResult::Reject(message)) => {
                // Canister crashing is interesting
                if message.contains("Canister trapped") {
                    return ExitKind::Crash;
                }
                0
            }
            Err(e) => match e.code() {
                ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => {
                    // println!("{e:?}");
                    // return ExitKind::Ok;
                    0
                }
                _ => 0,
            },
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

    fn cleanup(&self) {}

    fn input_dir(&self) -> PathBuf {
        self.0.input_dir()
    }

    fn crashes_dir(&self) -> PathBuf {
        self.0.crashes_dir()
    }

    fn corpus_dir(&self) -> PathBuf {
        self.0.corpus_dir()
    }

    #[allow(static_mut_refs)]
    fn set_coverage_map(&self) {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();
        let result = test.query(
            fuzzer_state.get_canister_id_by_name("candid_decode"),
            "export_coverage",
            vec![],
        );
        if let Ok(WasmResult::Reply(result)) = result {
            self.0.set_coverage_map(&result);
        }
    }

    fn get_coverage_map(&self) -> &mut [u8] {
        self.0.get_mut_coverage_map()
    }
}

fn run<T>(mut orchestrator: T)
where
    T: FuzzerOrchestrator,
{
    orchestrator.init();

    let mut harness = |input: &BytesInput| {
        orchestrator.setup();
        let result = orchestrator.execute(input.clone());
        orchestrator.set_coverage_map();
        orchestrator.cleanup();
        result
    };

    let decoding_map_observer = unsafe {
        RefCellValueObserver::new(
            DECODING_MAP_OBSERVER_NAME,
            libafl_bolts::ownedref::OwnedRef::from_ptr(addr_of!(MAP)),
        )
    };

    let decoding_feedback = DecodingMapFeedback::new();
    let hitcount_map_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::new("coverage_map", orchestrator.get_coverage_map())
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
        InMemoryOnDiskCorpus::no_meta(orchestrator.input_dir()).unwrap(),
        InMemoryOnDiskCorpus::no_meta(orchestrator.crashes_dir()).unwrap(),
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
    let paths = fs::read_dir(orchestrator.corpus_dir()).unwrap();
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
