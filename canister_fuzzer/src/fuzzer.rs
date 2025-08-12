use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::sync::Arc;
use std::{env, path::PathBuf, slice::IterMut};

pub struct FuzzerState {
    state: Option<Arc<StateMachine>>,
    pub canisters: Vec<CanisterInfo>,
    fuzzer_dir: String,
}

pub struct CanisterInfo {
    pub id: Option<CanisterId>,
    pub name: String,
    pub env_var: String,
}

impl FuzzerState {
    pub fn new(canisters: Vec<CanisterInfo>, fuzzer_dir: String) -> Self {
        Self {
            state: None,
            canisters,
            fuzzer_dir,
        }
    }

    pub fn init_state(&mut self, state: StateMachine) {
        self.state = Some(Arc::new(state));
    }

    pub fn get_state_machine(&self) -> Arc<StateMachine> {
        self.state.as_ref().unwrap().clone()
    }

    pub fn get_fuzzer_dir(&self) -> String {
        self.fuzzer_dir.clone()
    }

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

    pub fn get_iter_mut_canister_info(&mut self) -> IterMut<CanisterInfo> {
        self.canisters.iter_mut()
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
