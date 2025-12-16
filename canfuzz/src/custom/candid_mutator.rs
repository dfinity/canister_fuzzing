use candid::types::Type;
use candid::{IDLArgs, IDLValue, Int, Nat, Principal, TypeEnv};
use candid_parser::typing::pretty_check_file;
use core::marker::PhantomData;
use libafl::inputs::HasMutatorBytes;
use libafl::inputs::ResizableMutator;
use libafl::{
    Error,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
};
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;
use num_bigint::{BigInt, BigUint};
use num_traits::{PrimInt, WrappingAdd, WrappingSub};
use rand::{Rng, SeedableRng};
use std::borrow::Cow;

use crate::orchestrator::CandidTypeDefArgs;

pub struct CandidParserMutator<S> {
    is_enabled: bool,
    _env: TypeEnv,
    _arg_types: Vec<Type>,
    _method_name: Option<String>,
    phantom: PhantomData<S>,
}

impl<S> CandidParserMutator<S> {
    pub fn new(candid_def: Option<CandidTypeDefArgs>) -> Self {
        if candid_def.is_none() {
            return Self {
                is_enabled: false,
                _env: TypeEnv::new(),
                _arg_types: vec![],
                _method_name: None,
                phantom: PhantomData,
            };
        }
        // Initially, we will depend on corpus to develop and modify the type values
        // But we need the method defs to test subtype relations

        let candid_def = candid_def.unwrap();
        let (env, actor, _) = pretty_check_file(&candid_def.def).expect("Unable to parse did file");
        let actor = actor.unwrap();
        let func = env.get_method(&actor, &candid_def.method).unwrap();
        let types = &func.args;

        Self {
            is_enabled: true,
            _env: env.clone(),
            _arg_types: types.to_vec(),
            _method_name: Some(candid_def.method.to_string()),
            phantom: PhantomData,
        }
    }
}

impl<S> Named for CandidParserMutator<S> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CandidParserMutator")
    }
}

impl<S, I> Mutator<I, S> for CandidParserMutator<S>
where
    S: HasRand + HasCorpus<I>,
    I: Input + HasMutatorBytes + ResizableMutator<u8>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if self.is_enabled == false {
            return Ok(MutationResult::Skipped);
        }

        let mut args = match IDLArgs::from_bytes(input.mutator_bytes()) {
            Ok(a) => a,
            Err(_) => return Ok(MutationResult::Skipped),
        };

        let state_u64 = state.rand_mut().next();
        let mut rng = rand::rngs::StdRng::seed_from_u64(state_u64 as u64);

        if !args.args.is_empty() {
            let index = rng.random_range(0..args.args.len());
            if let Some(val) = args.args.get_mut(index) {
                mutate_value(val, &mut rng, 0);
            }
        } else {
            return Ok(MutationResult::Mutated);
        }

        let new_bytes = match args.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return Ok(MutationResult::Skipped),
        };

        input.resize(0, 0);
        input.extend(&new_bytes);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

fn mutate_value<R: Rng>(val: &mut IDLValue, rng: &mut R, depth: usize) {
    if depth > 20 {
        return;
    }

    match val {
        IDLValue::Bool(b) => *b = !*b,
        IDLValue::Null => {}
        IDLValue::Text(s) => mutate_text(s, rng),
        IDLValue::Int(i) => mutate_int(i, rng),
        IDLValue::Nat(n) => mutate_nat(n, rng),
        IDLValue::Float32(f) => *f = mutate_float(*f, rng),
        IDLValue::Float64(f) => *f = mutate_float(*f, rng),
        IDLValue::Vec(v) => mutate_vec(v, rng, depth),
        IDLValue::Opt(_o) => todo!(),
        IDLValue::Int8(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int16(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int32(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int64(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Nat8(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat16(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat32(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat64(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Record(fields) => {
            if !fields.is_empty() {
                let idx = rng.random_range(0..fields.len());
                mutate_value(&mut fields[idx].val, rng, depth + 1);
            }
        }
        IDLValue::Variant(v) => {
            mutate_value(&mut v.0.val, rng, depth + 1);
        }
        IDLValue::Principal(p) => mutate_principal(p, rng),
        IDLValue::Number(_) => todo!(),
        IDLValue::Blob(_items) => todo!(),
        IDLValue::Service(_principal) => todo!(),
        IDLValue::Func(_principal, _) => todo!(),
        IDLValue::None => todo!(),
        IDLValue::Reserved => todo!(),
    }
}

fn mutate_text<R: Rng>(s: &mut String, rng: &mut R) {
    match rng.random_range(0..4) {
        0 => s.push_str("FUZZ"), // Append
        1 => {
            if !s.is_empty() {
                s.pop();
            }
        } // Truncate
        2 => *s = String::from(""), // Empty
        3 => {
            // Bit flip a random char
            if !s.is_empty() {
                // This is a naive byte flip, might produce invalid utf8, which Candid handles safely
                // generally you want to insert known "naughty strings" here.
                unsafe {
                    let v = s.as_mut_vec();
                    let idx = rng.random_range(0..v.len());
                    v[idx] = v[idx].wrapping_add(1);
                }
            }
        }
        _ => {}
    }
}

fn mutate_int<R: Rng>(i: &mut Int, rng: &mut R) {
    // Candid Int is a wrapper around BigInt
    let val = &i.0;
    let new_val = match rng.random_range(0..4) {
        0 => val + 1,
        1 => val - 1,
        2 => BigInt::from(0),
        3 => BigInt::from(i64::MIN), // Boundary values
        _ => val.clone(),
    };
    *i = Int(new_val);
}

fn mutate_nat<R: Rng>(n: &mut Nat, rng: &mut R) {
    let val = &n.0;
    let new_val = match rng.random_range(0..4) {
        0 => val + 1u32,
        1 => {
            if val > &BigUint::from(0u32) {
                val - 1u32
            } else {
                BigUint::from(0u32)
            }
        }
        2 => BigUint::from(u64::MAX),
        3 => BigUint::from(0u32),
        _ => val.clone(),
    };
    *n = Nat(new_val);
}

fn mutate_float<F: num_traits::Float + Copy, R: Rng>(f: F, rng: &mut R) -> F {
    if rng.random_bool(0.1) {
        return F::nan();
    }
    if rng.random_bool(0.1) {
        return F::infinity();
    }
    f + F::from(1.0).unwrap() // Simple increment
}

fn mutate_vec<R: Rng>(vec: &mut Vec<IDLValue>, rng: &mut R, depth: usize) {
    if vec.is_empty() {
        // If empty, we can't easily add an item because generic IDLValue::Vec
        // doesn't inherently know what inner type to manufacture without looking at schema.
        // We could duplicate logic if we had the schema, but generic fuzzing usually assumes
        // non-empty corpus.
        return;
    }

    match rng.random_range(0..3) {
        0 => {
            // Remove random element
            let idx = rng.random_range(0..vec.len());
            vec.remove(idx);
        }
        1 => {
            // Duplicate random element (easy way to add valid data)
            let idx = rng.random_range(0..vec.len());
            let val = vec[idx].clone();
            vec.push(val);
        }
        2 => {
            // Mutate an element inside
            let idx = rng.random_range(0..vec.len());
            mutate_value(&mut vec[idx], rng, depth + 1);
        }
        _ => {}
    }
}

fn mutate_principal<R: Rng>(p: &mut Principal, rng: &mut R) {
    // Management canister or anonymous
    if rng.random_bool(0.5) {
        *p = Principal::management_canister();
    } else {
        *p = Principal::anonymous();
    }
}

// A highly aggressive primitive mutator favoring bit-level manipulation.
/// Works for any type T that behaves like a primitive integer (u8..u64, i8..i64).
fn mutate_primitive<T, R>(val: T, rng: &mut R) -> T
where
    T: PrimInt + std::fmt::Debug + WrappingAdd + WrappingSub, // PrimInt gives us bitwise ops (>>, <<, ^, |, &)
    R: Rng,
{
    // We want bit flips to be "prominent", so we give them high probability.
    // 0-40:  Single Bit Flip
    // 41-60: Two Bit Flip
    // 61-75: Byte Flip (Mask 0xFF)
    // 76-85: Arithmetic (+/- 1)
    // 86-95: Boundary (MIN/MAX/0)
    // 96-99: Havoc (Random)

    let mutation_type = rng.random_range(0..100);
    let bit_width = std::mem::size_of::<T>() * 8;

    match mutation_type {
        // --- Single Bit Flip (High Priority) ---
        0..=40 => {
            let bit_idx = rng.random_range(0..bit_width);
            // 1 << bit_idx
            let mask = T::one() << bit_idx;
            val ^ mask
        }

        // --- Two Bit Flips ---
        41..=60 => {
            let bit1 = rng.random_range(0..bit_width);
            let bit2 = rng.random_range(0..bit_width);
            let mask1 = T::one() << bit1;
            let mask2 = T::one() << bit2;
            val ^ (mask1 | mask2)
        }

        // --- Byte Flip (XOR with 0xFF at random position) ---
        61..=75 => {
            if bit_width <= 8 {
                // For u8/i8, this is just a full inversion
                !val
            } else {
                // Select a byte alignment (0, 8, 16, 32...)
                let shift = rng.random_range(0..(std::mem::size_of::<T>())) * 8;
                // Create mask 0xFF cast to T
                let byte_mask = T::from(0xFFu8).unwrap();
                let mask = byte_mask << shift;
                val ^ mask
            }
        }

        // --- Arithmetic (Standard Fuzzing) ---
        76..=85 => {
            if rng.random_bool(0.5) {
                val.wrapping_add(&T::one())
            } else {
                val.wrapping_sub(&T::one())
            }
        }

        // --- Boundaries (Edge Cases) ---
        86..=95 => match rng.random_range(0..3) {
            0 => T::min_value(),
            1 => T::max_value(),
            _ => T::zero(),
        },

        // --- Havoc (Complete random replacement) ---
        _ => {
            // Generates a random u64, casts it to T.
            // Since T might be small (u8), we let the cast truncate naturally.
            // Note: FromPrimitive returns Option, but usually simple casting via `as` is hard in generics.
            // We can cheat by creating random bytes and reading them.
            // Or simpler: XOR with a random mask of full width.

            // Create a random mask from u128 to cover all sizes up to u64/i64 easily
            let rand_bits = rng.random::<u128>();
            let mask = T::from(rand_bits & 0xFFFFFFFFFFFFFFFF).unwrap_or_else(|| T::zero());
            // In case T::from fails (it shouldn't for primitives), we fallback to bit flip.

            // Actually, simply XORing the current value with random bits = random value
            val ^ mask
        }
    }
}
