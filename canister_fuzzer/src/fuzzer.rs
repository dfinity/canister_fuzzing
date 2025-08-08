use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::path::PathBuf;

pub struct FuzzerState<'a> {
    pub state: Option<&'a StateMachine>,
    pub canisters: Vec<CanisterInfo>,
    pub fuzzer_dir: PathBuf,
}

pub struct CanisterInfo {
    pub id: Option<CanisterId>,
    pub name: String,
    pub env_var: String,
}

impl FuzzerState<'_> {
    pub fn get_cansiter_id_by_name(&self, name: &str) -> CanisterId {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .expect(format!("Canister {name} not found").as_str())
            .id
            .expect(format!("CanisterId is not initialized for {name}").as_str())
    }

    pub fn get_cansiter_env_by_name(&self, name: &str) -> String {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .expect(format!("Canister {name} not found").as_str())
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
