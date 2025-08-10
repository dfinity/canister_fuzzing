use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};

use crate::orchestrator::FuzzerOrchestrator;

pub fn sandbox_main<F, O>(mut actual_main: F, orchestrator: O)
where
    F: FnMut(O),
    O: FuzzerOrchestrator,
{
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
    } else {
        actual_main(orchestrator);
    }
}

pub fn test_sandbox_main<F, O>(mut actual_main: F, orchestrator: O, bytes: Vec<u8>)
where
    F: FnMut(O, Vec<u8>),
    O: FuzzerOrchestrator,
{
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
    } else {
        actual_main(orchestrator, bytes);
    }
}
