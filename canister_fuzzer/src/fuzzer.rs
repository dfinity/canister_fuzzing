use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use std::sync::Arc;
use std::{env, path::PathBuf, slice::IterMut};

/// Represents the global state for a fuzzing campaign.
///
/// This struct holds a reference to the IC `StateMachine`, a list of all
/// canisters under test, and the directory for fuzzer-specific artifacts.
pub struct FuzzerState {
    /// The IC state machine used to execute canister calls in a simulated environment.
    /// It's wrapped in an `Arc` to allow shared, thread-safe access.
    state: Option<Arc<StateMachine>>,
    /// A list of all canisters involved in the fuzzing setup.
    canisters: Vec<CanisterInfo>,
    /// The name of the fuzzer-specific directory.
    fuzzer_dir: String,
}

/// Contains information describing a single canister used in the fuzzer.
pub struct CanisterInfo {
    /// The runtime ID of the canister. This is `None` until the canister is
    /// installed in the state machine.
    pub id: Option<CanisterId>,
    /// A unique friendly name to identify the canister within the fuzzer.
    pub name: String,
    /// The name of the environment variable that holds the path to the canister's Wasm module.
    pub env_var: String,
    pub ty: CanisterType,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CanisterType {
    Coverage,
    Support,
}

impl FuzzerState {
    /// Creates a new `FuzzerState`.
    ///
    /// # Arguments
    ///
    /// * `canisters` - A vector of `CanisterInfo` structs, one for each canister to be fuzzed.
    /// * `fuzzer_dir` - A string identifying the directory for this fuzzer's artifacts.
    pub fn new(canisters: Vec<CanisterInfo>, fuzzer_dir: String) -> Self {
        assert!(
            canisters
                .iter()
                .filter(|c| c.ty == CanisterType::Coverage)
                .count()
                == 1,
            "Only one coverage canister is allowed"
        );
        Self {
            state: None,
            canisters,
            fuzzer_dir,
        }
    }

    /// Initializes the state machine for the fuzzer.
    pub fn init_state(&mut self, state: StateMachine) {
        self.state = Some(Arc::new(state));
    }

    /// Returns the `CanisterId` of the coverage canister.
    pub(crate) fn get_coverage_canister_id(&self) -> CanisterId {
        self.canisters
            .iter()
            .find(|c| c.ty == CanisterType::Coverage)
            .unwrap()
            .id
            .unwrap()
    }

    /// Returns a thread-safe reference to the state machine.
    ///
    /// # Panics
    ///
    /// Panics if the state machine has not been initialized via `init_state`.
    pub(crate) fn get_state_machine(&self) -> Arc<StateMachine> {
        self.state.as_ref().unwrap().clone()
    }

    /// Returns the fuzzer-specific directory name.
    pub(crate) fn get_fuzzer_dir(&self) -> String {
        self.fuzzer_dir.clone()
    }

    /// Retrieves a canister's `CanisterId` by its friendly name.
    ///
    /// # Panics
    ///
    /// Panics if no canister with the given `name` is found, or if the
    /// found canister's ID has not been initialized yet.
    pub fn get_canister_id_by_name(&self, name: &str) -> CanisterId {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .id
            .unwrap_or_else(|| panic!("CanisterId is not initialized for {name}"))
    }

    /// Retrieves the environment variable name for a canister's Wasm path by its friendly name.
    ///
    /// # Panics
    ///
    /// Panics if no canister with the given `name` is found.
    pub fn get_canister_env_by_name(&self, name: &str) -> String {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .env_var
            .clone()
    }

    /// Returns a vector containing the names of all registered canisters.
    pub fn get_canister_names(&self) -> Vec<String> {
        self.canisters.iter().map(|c| c.name.clone()).collect()
    }

    /// Returns a mutable iterator over the `CanisterInfo` vector.
    ///
    /// This is useful during the setup phase to populate the `id` field
    /// for each canister after it has been created in the state machine.
    pub fn get_iter_mut_canister_info(&mut self) -> IterMut<CanisterInfo> {
        self.canisters.iter_mut()
    }

    /// A utility function to locate the project's `target` directory.
    pub(crate) fn get_target_dir() -> PathBuf {
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
    }
}
