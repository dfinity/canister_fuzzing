use libafl::{
    inputs::ValueInput,
    stages::{AflStatsStage, CalibrationStage},
};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

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

pub trait FuzzerOrchestrator {
    fn init(&mut self);
    fn setup(&self);
    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind;
    fn cleanup(&self);

    fn input_dir(&self) -> PathBuf;
    fn crashes_dir(&self) -> PathBuf;
    fn corpus_dir(&self) -> PathBuf;

    fn set_coverage_map(&self);
    fn get_coverage_map(&self) -> &mut [u8];
}

pub fn run<T>(mut orchestrator: T)
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

    let hitcount_map_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::new("coverage_map", orchestrator.get_coverage_map())
    });
    let afl_map_feedback = AflMapFeedback::new(&hitcount_map_observer);
    let mut feedback = afl_map_feedback;
    let mut objective = CrashFeedback::new();

    let calibration_stage = CalibrationStage::new(&feedback);
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
        tuple_list!(hitcount_map_observer),
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

pub fn test_one_input<T>(mut orchestrator: T, bytes: Vec<u8>)
where
    T: FuzzerOrchestrator,
{
    orchestrator.init();
    orchestrator.setup();
    let result = orchestrator.execute(ValueInput::new(bytes));
    orchestrator.cleanup();
    println!("Execution result: {result:?}");
}
