use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::{env, path::PathBuf};

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

    pub(crate) fn get_target_dir() -> PathBuf {
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
    }
}
