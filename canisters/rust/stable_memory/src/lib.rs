use arbitrary::Arbitrary;
use candid::{CandidType, Decode};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableMinHeap, StableVec};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

mod data;
use data::{BoundedFuzzStruct, MAX_VALUE_SIZE, UnboundedFuzzStruct};

const KEY_SIZE: usize = 4;
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static BOUNDED_BTREEMAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], BoundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static UNBOUNDED_BTREEMAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], UnboundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    static BOUNDED_MINHEAP: RefCell<StableMinHeap<BoundedFuzzStruct, Memory>> = RefCell::new(
        StableMinHeap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
    );

    static BOUNDED_VEC: RefCell<StableVec<BoundedFuzzStruct, Memory>> = RefCell::new(
        StableVec::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
        )
    );
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum StableStructOperation {
    BTreeMapInsert { key: [u8; KEY_SIZE], value: Vec<u8> },
    BTreeMapRemove { index: u16 },
    BTreeMapPopFirst,
    BTreeMapPopLast,
    MinHeapPush { value: Vec<u8> },
    MinHeapPop,
    VecPush { value: Vec<u8> },
    VecPop,
}

#[unsafe(export_name = "canister_update stable_memory_ops")]
pub fn stable_memory_ops() {
    let ops = candid::Decode!(&ic_cdk::api::msg_arg_data(), Vec<StableStructOperation>)
        .unwrap_or_default();
    let mut remove_keys: Vec<[u8; KEY_SIZE]> = Vec::new();

    for op in ops {
        match op {
            StableStructOperation::BTreeMapInsert { key, value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.insert(key, BoundedFuzzStruct { data: bounded_data });
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.insert(key, UnboundedFuzzStruct { data: value });
                });

                remove_keys.push(key);
            }
            StableStructOperation::BTreeMapRemove { index } => {
                if remove_keys.is_empty() {
                    continue;
                }

                let key_index = index as usize % remove_keys.len();
                let key = remove_keys.remove(key_index);

                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.remove(&key.clone());
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.remove(&key.clone());
                });
            }
            StableStructOperation::BTreeMapPopFirst => {
                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_first();
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_first();
                });
            }
            StableStructOperation::BTreeMapPopLast => {
                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_last();
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_last();
                });
            }
            StableStructOperation::MinHeapPush { value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_MINHEAP.with_borrow_mut(|stable_minheap| {
                    stable_minheap.push(&BoundedFuzzStruct { data: bounded_data });
                });
            }
            StableStructOperation::MinHeapPop => {
                BOUNDED_MINHEAP.with_borrow_mut(|stable_minheap| {
                    stable_minheap.pop();
                });
            }
            StableStructOperation::VecPush { value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_VEC.with_borrow_mut(|stable_vec| {
                    stable_vec.push(&BoundedFuzzStruct { data: bounded_data });
                });
            }
            StableStructOperation::VecPop => {
                BOUNDED_VEC.with_borrow_mut(|stable_vec| {
                    stable_vec.pop();
                });
            }
        }
    }
    ic_cdk::api::msg_reply([]);
}
