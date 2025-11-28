use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;
use std::sync::Arc;
use std::{path::PathBuf, slice::IterMut};

/// Represents the global state for a fuzzing campaign.
///
/// This struct holds a reference to the `PocketIc` instance (the IC state machine), a list of all
/// canisters under test, and a name for the fuzzer, which is used to create directories for
/// artifacts like the input and crashes.
pub struct FuzzerState {
    name: String,
    /// The `PocketIc` instance used to execute canister calls in a simulated environment.
    /// It's wrapped in an `Arc` to allow shared, thread-safe access, and an `Option`
    /// because it's initialized after the `FuzzerState` is created.
    state: Option<Arc<PocketIc>>,
    /// A list of all canisters involved in the fuzzing setup.
    canisters: Vec<CanisterInfo>,
}

/// Contains information describing a single canister used in the fuzzer.
pub struct CanisterInfo {
    /// The runtime ID of the canister. This is `None` until the canister is
    /// installed in the state machine.
    pub id: Option<CanisterId>,
    /// A unique friendly name to identify the canister within the fuzzer.
    pub name: String,
    /// The path to the canister's Wasm module, specified either directly or via an environment variable.
    pub wasm_path: WasmPath,
    /// The type of the canister, indicating its role in the fuzzing setup.
    pub ty: CanisterType,
}

/// Defines the role of a canister in the fuzzing setup.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CanisterType {
    /// The canister that is instrumented for code coverage.
    /// There must be exactly one coverage canister.
    Coverage,
    /// A supporting canister that is part of the test environment but not instrumented for coverage.
    Support,
}

/// Specifies how to locate a canister's Wasm module.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum WasmPath {
    /// The Wasm path is stored in an environment variable.
    EnvVar(String),
    /// The Wasm path is a direct file path.
    Path(PathBuf),
}

impl FuzzerState {
    /// Creates a new `FuzzerState`.
    ///
    /// # Arguments
    ///
    /// * `name` - A unique name for the fuzzer, used for artifact directories.
    /// * `canisters` - A vector of `CanisterInfo` structs, one for each canister involved in the test.
    pub fn new(name: &str, canisters: Vec<CanisterInfo>) -> Self {
        assert!(
            canisters
                .iter()
                .filter(|c| c.ty == CanisterType::Coverage)
                .count()
                == 1,
            "Only one coverage canister is allowed"
        );
        Self {
            name: name.to_string(),
            state: None,
            canisters,
        }
    }

    /// Initializes the state machine for the fuzzer.
    pub fn init_state(&mut self, state: PocketIc) {
        self.state = Some(Arc::new(state));
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the `CanisterId` of the coverage canister.
    ///
    /// # Panics
    ///
    /// Panics if the coverage canister's ID has not been set.
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
    pub(crate) fn get_state_machine(&self) -> Arc<PocketIc> {
        self.state.as_ref().unwrap().clone()
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

    /// Retrieves a canister's Wasm path by its friendly name.
    ///
    /// # Panics
    ///
    /// Panics if no canister with the given `name` is found.
    pub fn get_canister_wasm_path_by_name(&self, name: &str) -> WasmPath {
        self.canisters
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("Canister {name} not found"))
            .wasm_path
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
    pub fn get_iter_mut_canister_info(&mut self) -> IterMut<'_, CanisterInfo> {
        self.canisters.iter_mut()
    }
}
