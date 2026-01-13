use candid::{Decode, Encode, Principal};
use canfuzz::libafl::executors::ExitKind;
use canfuzz::libafl::inputs::ValueInput;
use k256::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::{
    Scalar, Secp256k1,
    ecdsa::{Signature, hazmat},
};
use pocket_ic::PocketIcBuilder;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

use slog::Level;

use canfuzz::FuzzerState;
use canfuzz::fuzzer::{CanisterBuilder, FuzzerBuilder, FuzzerState};
use canfuzz::instrumentation::{InstrumentationArgs, Seed, instrument_wasm_for_fuzzing};
use canfuzz::orchestrator::FuzzerOrchestrator;
use canfuzz::util::{parse_canister_result_for_trap, read_canister_bytes};

fn main() {
    let canister = CanisterBuilder::new("ecdsa_sign")
        .with_wasm_env("MOTOKO_CANISTER_WASM_PATH")
        .as_coverage()
        .build();

    let state = FuzzerBuilder::new()
        .name("motoko_diff")
        .with_canister(canister)
        .build();

    let mut fuzzer_state = MotokoDiffFuzzer(state);
    fuzzer_state.run();
}

#[derive(FuzzerState)]
struct MotokoDiffFuzzer(FuzzerState);

impl FuzzerOrchestrator for MotokoDiffFuzzer {
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
            });
            test.install_canister(canister_id, module, vec![], None);
            info.id = Some(canister_id);
        }
    }

    fn execute(&self, input: ValueInput<Vec<u8>>) -> ExitKind {
        let test = self.get_state_machine();

        let bytes: Vec<u8> = input.into();
        if bytes.len() < 64 {
            return ExitKind::Ok;
        }

        let mut key = [0u8; 32];
        let key_inner = Scalar::reduce(U256::from_be_slice(&bytes[..32]));
        key.copy_from_slice(&key_inner.to_bytes());

        let mut k = [0u8; 32];
        let k_inner = Scalar::reduce(U256::from_be_slice(&bytes[32..64]));
        k.copy_from_slice(&k_inner.to_bytes());

        if key.iter().all(|&x| x == 0) || k.iter().all(|&x| x == 0) {
            return ExitKind::Ok;
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes[64..]);

        let digest = hasher.finalize();
        let msg = digest.to_vec();
        let payload = candid::Encode!(&msg, &key, &k).unwrap();
        let result = test.update_call(
            self.get_coverage_canister_id(),
            Principal::anonymous(),
            "sign_ecdsa",
            payload,
        );

        let exit_status = parse_canister_result_for_trap(result.clone());

        let exit_status = if exit_status == ExitKind::Ok
            && let Ok(result) = result
        {
            let result = Decode!(&result, Vec<u8>).unwrap();
            if let Ok((signature, _)) =
                hazmat::sign_prehashed::<Secp256k1, Scalar>(&key_inner, k_inner, &digest)
            {
                let signature_old = Signature::from_der(&result).unwrap();
                if signature != signature_old {
                    return ExitKind::Crash;
                }
            }
            ExitKind::Ok
        } else {
            exit_status
        };

        test.advance_time(Duration::from_secs(60));
        exit_status
    }
}
