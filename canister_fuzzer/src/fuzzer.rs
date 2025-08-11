use chrono::Local;
use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::{env, fs, path::PathBuf};

use crate::constants::AFL_COVERAGE_MAP_SIZE;

pub struct FuzzerState {
    pub state: Option<StateMachine>,
    pub canisters: Vec<CanisterInfo>,
    pub fuzzer_dir: String,
}

pub struct CanisterInfo {
    pub id: Option<CanisterId>,
    pub name: String,
    pub env_var: String,
}

static mut COVERAGE_MAP: &mut [u8] = &mut [0; AFL_COVERAGE_MAP_SIZE as usize];

impl FuzzerState {
    pub fn get_canister_id_by_name(&self, name: &str) -> CanisterId {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .id
            .unwrap_or_else(|| panic!("CanisterId is not initialized for {name}"))
    }

    pub fn get_canister_env_by_name(&self, name: &str) -> String {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .env_var
            .clone()
    }

    pub fn get_canister_names(&self) -> Vec<String> {
        self.canisters.iter().map(|c| c.name.clone()).collect()
    }

    pub fn get_root_dir(&self) -> PathBuf {
        get_target_dir()
            .parent()
            .unwrap()
            .join(self.fuzzer_dir.clone())
    }

    #[allow(static_mut_refs)]
    pub fn set_coverage_map(&self, slice: &[u8]) {
        unsafe { COVERAGE_MAP.copy_from_slice(slice) };
    }

    pub fn get_mut_coverage_map(&self) -> &'static mut [u8] {
        unsafe { COVERAGE_MAP }
    }

    pub fn input_dir(&self) -> PathBuf {
        let input_dir = get_target_dir()
            .join("artifacts")
            .join(self.fuzzer_dir.clone())
            .join(Local::now().format("%Y%m%d_%H%M").to_string())
            .join("input");
        fs::create_dir_all(&input_dir).unwrap();
        input_dir
    }

    pub fn crashes_dir(&self) -> PathBuf {
        let crashes_dir = get_target_dir()
            .join("artifacts")
            .join(self.fuzzer_dir.clone())
            .join(Local::now().format("%Y%m%d_%H%M").to_string())
            .join("crashes");
        fs::create_dir_all(&crashes_dir).unwrap();
        crashes_dir
    }

    pub fn corpus_dir(&self) -> PathBuf {
        self.get_root_dir().join("corpus")
    }
}

fn get_target_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
}
