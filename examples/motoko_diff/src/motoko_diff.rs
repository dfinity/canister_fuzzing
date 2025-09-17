use candid::{Decode, Encode, Principal};
use canister_fuzzer::libafl::executors::ExitKind;
use canister_fuzzer::libafl::inputs::ValueInput;
use k256::elliptic_curve::PrimeField;
use k256::{
    Scalar, Secp256k1,
    ecdsa::{Signature, hazmat},
};
use pocket_ic::PocketIcBuilder;
use sha2::{Digest, Sha256};
use std::time::Duration;

use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, CanisterType, FuzzerState, WasmPath};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{FuzzerOrchestrator, FuzzerStateProvider};
use canister_fuzzer::util::{parse_canister_result_for_trap, read_canister_bytes};

fn main() {
    let mut fuzzer_state = MotokoDiffFuzzer(FuzzerState::new(
        vec![CanisterInfo {
            id: None,
            name: "ecdsa_sign".to_string(),
            wasm_path: WasmPath::EnvVar("MOTOKO_CANISTER_WASM_PATH".to_string()),
            ty: CanisterType::Coverage,
        }],
        "examples/motoko_diff".to_string(),
    ));
    fuzzer_state.run();
}

struct MotokoDiffFuzzer(FuzzerState);

impl FuzzerStateProvider for MotokoDiffFuzzer {
    fn get_fuzzer_state(&self) -> &FuzzerState {
        &self.0
    }
}

impl FuzzerOrchestrator for MotokoDiffFuzzer {
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
            let module = instrument_wasm_for_fuzzing(&read_canister_bytes(info.wasm_path.clone()));
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let b = digest.as_slice().to_vec();
        let payload = candid::Encode!(&b, &key, &k).unwrap();
        let result = parse_canister_result_for_trap(test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "sign_ecdsa",
            payload,
        ));

        // Update main result here (test for hash)
        // let bytes: Vec<u8> = input.into();
        // let mut hasher = Sha256::new();
        // hasher.update(bytes);
        // let digest = hasher.finalize();
        // let b = digest.as_slice().to_vec();
        // let payload = candid::Encode!(&bytes).unwrap();
        // let result = test.update_call(fuzzer_state.get_canister_id_by_name("ecdsa_sign"), Principal::anonymous(), "sign_ecdsa", payload);

        let exit_status = if result.0 == ExitKind::Ok && result.1.is_some() {
            let result = Decode!(&result.1.unwrap(), Vec<u8>).unwrap();
            let d = Scalar::from_repr(key.into()).unwrap();
            let k = Scalar::from_repr(k.into()).unwrap();

            let (signature, _): (Signature, _) =
                hazmat::sign_prehashed::<Secp256k1, Scalar>(&d, k, &digest).unwrap();
            let signature_old = Signature::from_der(&result).unwrap();

            if signature != signature_old {
                return ExitKind::Crash;
            }
            ExitKind::Ok
        } else {
            ExitKind::Crash
        };

        test.advance_time(Duration::from_secs(1));
        test.tick();
        exit_status
    }
}
