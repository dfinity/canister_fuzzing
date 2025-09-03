use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main, embed_sandbox_signature,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG, SANDBOX_MAGIC_BYTES,
};

embed_sandbox_signature!();

pub fn sandbox_main<F>(mut actual_main: F)
where
    F: FnMut(),
{
    unsafe {
        core::ptr::read_volatile(&SANDBOX_SIGNATURE);
    }

    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
    } else {
        actual_main();
    }
}
