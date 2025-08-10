use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::path::PathBuf;

pub struct FuzzerState {
    pub state: Option<StateMachine>,
    pub canisters: Vec<CanisterInfo>,
    pub fuzzer_dir: PathBuf,
}

pub struct CanisterInfo {
    pub id: Option<CanisterId>,
    pub name: String,
    pub env_var: String,
}

impl FuzzerState {
    pub fn get_cansiter_id_by_name(&self, name: &str) -> CanisterId {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .id
            .unwrap_or_else(|| panic!("CanisterId is not initialized for {name}"))
    }

    pub fn get_cansiter_env_by_name(&self, name: &str) -> String {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .env_var
            .clone()
    }

    pub fn get_cansiter_names(&self) -> Vec<String> {
        self.canisters.iter().map(|c| c.name.clone()).collect()
    }

    pub fn get_root_dir(&self) -> PathBuf {
        self.fuzzer_dir.clone()
    }
}
