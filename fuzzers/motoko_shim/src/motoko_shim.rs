use candid::Encode;
use ic_state_machine_tests::ErrorCode;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use once_cell::sync::Lazy;
use sandbox_shim::sandbox_main;
use std::cell::RefCell;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use libafl::{
    corpus::inmemory_ondisk::InMemoryOnDiskCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
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
use slog::Level;

const EXECUTION_DIR: &str = "fuzzers/motoko_shim";
static mut TEST: Lazy<RefCell<(StateMachine, CanisterId)>> =
    Lazy::new(|| RefCell::new(create_execution_test()));
static mut COVERAGE_MAP: &mut [u8] = &mut [0; 65536];

fn read_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("MOTOKO_CANISTER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn create_execution_test() -> (StateMachine, CanisterId) {
    let test = StateMachineBuilder::new()
        .with_log_level(Some(Level::Critical))
        .build();

    let canister_id = test
        .install_canister_with_cycles(
            read_canister_bytes(),
            vec![],
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();
    (test, canister_id)
}

fn main() {
    sandbox_main(run);
}

#[allow(static_mut_refs)]
pub fn run() {
    let mut harness = |input: &BytesInput| {
        let canister_id = unsafe { TEST.borrow().1 };
        let test = unsafe { &mut TEST.borrow_mut().0 };

        // Update main result here
        let bytes: Vec<u8> = (*input).clone().into();
        let result = test.execute_ingress(canister_id, "parse_cbor", Encode!(&bytes).unwrap());
        // println!("{:?} result", result);

        let exit_status = match result {
            Ok(WasmResult::Reject(message)) => {
                // Canister crashing is interesting
                if message.contains("Canister trapped") {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            }
            Err(e) => match e.code() {
                ErrorCode::CanisterCalledTrap | ErrorCode::CanisterTrapped => ExitKind::Crash,
                _ => ExitKind::Ok,
            },
            _ => ExitKind::Ok,
        };

        test.advance_time(Duration::from_secs(1));
        test.tick();

        let result = test.query(canister_id, "export_coverage", vec![]);
        if let Ok(WasmResult::Reply(result)) = result {
            unsafe { COVERAGE_MAP.copy_from_slice(&result) };
        }

        // Maybe look into instructions consumed?
        exit_status
    };

    let hitcount_map_observer =
        HitcountsMapObserver::new(unsafe { StdMapObserver::new("coverage_map", COVERAGE_MAP) });
    let afl_map_feedback = AflMapFeedback::new(&hitcount_map_observer);
    let mut feedback = afl_map_feedback;
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryOnDiskCorpus::no_meta(PathBuf::from(format!("{EXECUTION_DIR}/input"))).unwrap(),
        InMemoryOnDiskCorpus::no_meta(PathBuf::from(format!("{EXECUTION_DIR}/crashes"))).unwrap(),
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
        tuple_list!(hitcount_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // bazel run @candid//:didc random -- -d gateway.did -t '(HttpResponse)' | bazel run @candid//:didc encode | xxd -r -p
    let paths = fs::read_dir(PathBuf::from(format!("{EXECUTION_DIR}/corpus"))).unwrap();
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
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
