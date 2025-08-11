use candid::{Decode, Encode};
use ic_state_machine_tests::ErrorCode;
use ic_state_machine_tests::StateMachineBuilder;
use ic_types::{ingress::WasmResult, Cycles};
use k256::elliptic_curve::PrimeField;
use k256::{
    ecdsa::{hazmat, Signature},
    Scalar, Secp256k1,
};
use libafl::executors::ExitKind;
use libafl::inputs::ValueInput;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

use slog::Level;

use canister_fuzzer::fuzzer::{CanisterInfo, FuzzerState};
use canister_fuzzer::instrumentation::instrument_wasm_for_fuzzing;
use canister_fuzzer::orchestrator::{self, FuzzerOrchestrator};
use canister_fuzzer::sandbox_shim::sandbox_main;
use canister_fuzzer::util::read_canister_bytes;

fn main() {
    let fuzzer_state = MotokoDiffFuzzer(FuzzerState {
        state: None,
        canisters: vec![CanisterInfo {
            id: None,
            name: "ecdsa_sign".to_string(),
            env_var: "MOTOKO_CANISTER_WASM_PATH".to_string(),
        }],
        fuzzer_dir: PathBuf::from("examples/motoko_diff"),
    });
    sandbox_main(orchestrator::run, fuzzer_state);
}

struct MotokoDiffFuzzer(FuzzerState);

impl FuzzerOrchestrator for MotokoDiffFuzzer {
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

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();

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
        let result = test.execute_ingress(
            fuzzer_state.get_cansiter_id_by_name("ecdsa_sign"),
            "sign_ecdsa",
            payload,
        );

        // Update main result here (test for hash)
        // let bytes: Vec<u8> = input.into();
        // let mut hasher = Sha256::new();
        // hasher.update(bytes);
        // let digest = hasher.finalize();
        // let b = digest.as_slice().to_vec();
        // let payload = candid::Encode!(&bytes).unwrap();
        // let result = test.execute_ingress(fuzzer_state.get_cansiter_id_by_name("ecdsa_sign"), "sign_ecdsa", payload);

        let exit_status = match result {
            Ok(WasmResult::Reply(bytes)) => {
                let result = Decode!(&bytes, Vec<u8>).unwrap();
                let d = Scalar::from_repr(key.into()).unwrap();
                let k = Scalar::from_repr(k.into()).unwrap();

                let (signature, _): (Signature, _) =
                    hazmat::sign_prehashed::<Secp256k1, Scalar>(&d, k, &digest).unwrap();
                let signature_old = Signature::from_der(&result).unwrap();

                if signature != signature_old {
                    return ExitKind::Crash;
                }
                ExitKind::Ok
            }
            Ok(WasmResult::Reject(message)) => {
                // Canister crashing is interesting
                if message.contains("Canister trapped") {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            }
            Err(e) => match e.code() {
                ErrorCode::CanisterTrapped | ErrorCode::CanisterCalledTrap => {
                    println!("{e:?} result");
                    ExitKind::Crash
                }
                _ => ExitKind::Ok,
            },
        };

        test.advance_time(Duration::from_secs(1));
        test.tick();
        exit_status
    }

    fn cleanup(&self) {}

    fn input_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("input")
    }

    fn crashes_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("crashes")
    }

    fn corpus_dir(&self) -> PathBuf {
        self.0.get_root_dir().join("corpus")
    }

    #[allow(static_mut_refs)]
    fn set_coverage_map(&self) {
        let fuzzer_state = &self.0;
        let test = fuzzer_state.state.as_ref().unwrap();
        let result = test.query(
            fuzzer_state.get_cansiter_id_by_name("ecdsa_sign"),
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
