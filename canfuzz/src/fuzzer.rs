use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;
use std::sync::Arc;
use std::{path::PathBuf, slice::IterMut};

use crate::util::read_canister_bytes;

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
#[derive(Clone, Debug)]
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
    /// Initialization arguments for the canister.
    pub init_args: Vec<u8>,
}

/// Defines the role of a canister in the fuzzing setup.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
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

    /// Returns a new `FuzzerBuilder` to construct a `FuzzerState`.
    pub fn builder() -> FuzzerBuilder {
        FuzzerBuilder::new()
    }

    /// Initializes the state machine for the fuzzer.
    pub fn init_state(&mut self, state: PocketIc) {
        self.state = Some(Arc::new(state));
    }

    /// Automatically sets up the environment by creating a PocketIC instance and installing all registered canisters.
    ///
    /// This method:
    /// 1. Creates a new `PocketIc` instance (if one isn't already set).
    /// 2. Iterates through all registered canisters.
    /// 3. Creates each canister on the IC.
    /// 4. Installs the Wasm code for each canister.
    /// 5. Updates the `CanisterInfo` with the assigned `CanisterId`.
    ///
    /// # Panics
    ///
    /// Panics if `PocketIc` cannot be initialized or if canister creation/installation fails.
    pub fn setup_canisters(&mut self) {
        if self.state.is_none() {
            let pic = PocketIc::new();
            self.init_state(pic);
        }

        let pic = self.get_state_machine();

        for canister_info in self.canisters.iter_mut() {
            let canister_id = pic.create_canister();
            pic.add_cycles(canister_id, 20_000_000_000_000);

            let wasm_bytes = read_canister_bytes(canister_info.wasm_path.clone());

            pic.install_canister(
                canister_id,
                wasm_bytes,
                canister_info.init_args.clone(),
                None,
            );

            canister_info.id = Some(canister_id);
            println!(
                "Installed canister '{}' at {}",
                canister_info.name, canister_id
            );
        }
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
            .expect("Coverage canister ID not set. Did you call setup_canisters()?")
    }

    /// Returns a thread-safe reference to the state machine.
    ///
    /// # Panics
    ///
    /// Panics if the state machine has not been initialized via `init_state`.
    pub(crate) fn get_state_machine(&self) -> Arc<PocketIc> {
        self.state
            .as_ref()
            .expect("PocketIC state not initialized")
            .clone()
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

/// A builder for creating `FuzzerState`.
pub struct FuzzerBuilder {
    name: String,
    canisters: Vec<CanisterInfo>,
}

impl FuzzerBuilder {
    pub fn new() -> Self {
        Self {
            name: "default_fuzzer".to_string(),
            canisters: Vec::new(),
        }
    }

    /// Sets the name of the fuzzer.
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    /// Adds a canister to the fuzzer configuration.
    pub fn with_canister(mut self, canister: CanisterInfo) -> Self {
        self.canisters.push(canister);
        self
    }

    /// Builds the `FuzzerState`.
    ///
    /// # Panics
    ///
    /// Panics if there is not exactly one coverage canister.
    pub fn build(self) -> FuzzerState {
        FuzzerState::new(&self.name, self.canisters)
    }
}

impl Default for FuzzerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A builder for creating `CanisterInfo`.
pub struct CanisterBuilder {
    name: String,
    wasm_path: Option<WasmPath>,
    ty: CanisterType,
    init_args: Vec<u8>,
}

impl CanisterBuilder {
    /// Starts building a new canister with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            wasm_path: None,
            ty: CanisterType::Support, // Default to Support
            init_args: Vec::new(),
        }
    }

    /// Sets the Wasm path from a file path.
    pub fn with_wasm_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.wasm_path = Some(WasmPath::Path(path.into()));
        self
    }

    /// Sets the Wasm path from an environment variable.
    pub fn with_wasm_env(mut self, env_var: &str) -> Self {
        self.wasm_path = Some(WasmPath::EnvVar(env_var.to_string()));
        self
    }

    /// Sets the initialization arguments for the canister.
    pub fn with_init_args(mut self, args: Option<Vec<u8>>) -> Self {
        self.init_args = args.unwrap_or_default();
        self
    }

    /// Marks this canister as the coverage target.
    pub fn as_coverage(mut self) -> Self {
        self.ty = CanisterType::Coverage;
        self
    }

    /// Marks this canister as a support canister (default).
    pub fn as_support(mut self) -> Self {
        self.ty = CanisterType::Support;
        self
    }

    /// Builds the `CanisterInfo`.
    ///
    /// # Panics
    ///
    /// Panics if the Wasm path has not been set.
    pub fn build(self) -> CanisterInfo {
        CanisterInfo {
            id: None,
            name: self.name,
            wasm_path: self.wasm_path.expect("Wasm path must be set"),
            ty: self.ty,
            init_args: self.init_args,
        }
    }
}
