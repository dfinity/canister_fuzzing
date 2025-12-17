use candid::types::{Type, TypeInner};
use candid::{IDLArgs, IDLValue, Int, Nat, Principal, TypeEnv};
use candid_parser::configs::{Configs, Scope, ScopePos};
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
use num_traits::{PrimInt, WrappingAdd, WrappingMul, WrappingSub};
use rand::distr::{Distribution, StandardUniform};
use rand::{Rng, SeedableRng};
use std::borrow::Cow;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

pub struct CandidTypeDefArgs {
    pub def: PathBuf,
    pub method: String,
}

pub struct CandidParserMutator<S> {
    is_enabled: bool,
    env: TypeEnv,
    arg_types: Vec<Type>,
    method_name: Option<String>,
    phantom: PhantomData<S>,
}

impl<S> CandidParserMutator<S> {
    pub fn new(candid_def: Option<CandidTypeDefArgs>) -> Self {
        if candid_def.is_none() {
            return Self {
                is_enabled: false,
                env: TypeEnv::new(),
                arg_types: vec![],
                method_name: None,
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
            env: env.clone(),
            arg_types: types.to_vec(),
            method_name: Some(candid_def.method.to_string()),
            phantom: PhantomData,
        }
    }

    fn mutate_random_generation<I, R>(
        &self,
        input: &mut I,
        rng: &mut R,
    ) -> Result<MutationResult, Error>
    where
        I: Input + HasMutatorBytes + ResizableMutator<u8>,
        R: Rng,
    {
        let config = Configs::from_str("").unwrap();

        let scope = self.method_name.as_ref().map(|method| Scope {
            position: Some(ScopePos::Arg),
            method,
        });

        let seed = rng.random::<u64>().to_le_bytes().to_vec();

        let new_args =
            match candid_parser::random::any(&seed, config, &self.env, &self.arg_types, &scope) {
                Ok(args) => args,
                Err(_) => return Ok(MutationResult::Skipped), // Schema mismatch or gen failure
            };

        let new_bytes = match new_args.to_bytes() {
            Ok(b) => b,
            Err(_) => return Ok(MutationResult::Skipped),
        };

        input.resize(0, 0);
        input.extend(&new_bytes);
        Ok(MutationResult::Mutated)
    }

    fn mutate_existing_bytes<I, R>(
        &self,
        input: &mut I,
        rng: &mut R,
    ) -> Result<MutationResult, Error>
    where
        I: Input + HasMutatorBytes + ResizableMutator<u8>,
        R: Rng,
    {
        let mut args = match IDLArgs::from_bytes(input.mutator_bytes()) {
            Ok(a) => {
                // This is a bit of a hack. We are trying to see if the decoded args are compatible
                // with the method signature. If not, we can't do type-aware mutation.
                // A better approach would be to store the types alongside the args in the corpus.
                let mut gamma = std::collections::HashSet::new();
                let decoded_types = a.get_types();
                if self.arg_types.len() == decoded_types.len()
                    && self
                        .arg_types
                        .iter()
                        .zip(decoded_types.iter())
                        .all(|(t1, t2)| {
                            candid::types::subtype::subtype(&mut gamma, &self.env, t2, t1).is_ok()
                        })
                {
                    a
                } else {
                    return Ok(MutationResult::Skipped);
                }
            }
            Err(_) => return Ok(MutationResult::Skipped),
        };

        if !args.args.is_empty() {
            let index = rng.random_range(0..args.args.len());
            mutate_value(
                &mut args.args[index],
                &self.arg_types[index],
                &self.env,
                rng,
                0,
            );
        }

        let new_bytes = match args.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return Ok(MutationResult::Skipped),
        };

        input.resize(0, 0);
        input.extend(&new_bytes);
        Ok(MutationResult::Mutated)
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
        let state_u64 = state.rand_mut().next();
        let mut rng = rand::rngs::StdRng::seed_from_u64(state_u64);

        // No mutation
        if !self.is_enabled {
            if rng.random_bool(0.05) {
                return self.mutate_random_generation(input, &mut rng);
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        // Enabled 20% random + 80% existing
        if rng.random_bool(0.2) {
            // We offload it to candid_parser::random for now, but later can replace
            // with our own strategy
            return self.mutate_random_generation(input, &mut rng);
        }

        self.mutate_existing_bytes(input, &mut rng)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        if let Some(id) = _new_corpus_id {
            println!("New corpus id {id:?}");
        }
        Ok(())
    }
}

fn mutate_value<R: Rng>(val: &mut IDLValue, ty: &Type, env: &TypeEnv, rng: &mut R, depth: usize) {
    if depth > 20 {
        return;
    }

    match val {
        IDLValue::Bool(b) => *b = !*b,
        IDLValue::Null => {}
        IDLValue::None => {}
        IDLValue::Reserved => {}

        IDLValue::Text(s) => mutate_text(s, rng),
        IDLValue::Number(s) => mutate_text(s, rng),

        IDLValue::Int(i) => mutate_int(i, rng),
        IDLValue::Int8(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int16(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int32(i) => *i = mutate_primitive(*i, rng),
        IDLValue::Int64(i) => *i = mutate_primitive(*i, rng),

        IDLValue::Nat(n) => mutate_nat(n, rng),
        IDLValue::Nat8(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat16(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat32(n) => *n = mutate_primitive(*n, rng),
        IDLValue::Nat64(n) => *n = mutate_primitive(*n, rng),

        IDLValue::Float32(f) => *f = mutate_float(*f, rng),
        IDLValue::Float64(f) => *f = mutate_float(*f, rng),

        IDLValue::Vec(v) => {
            if let Ok(TypeInner::Vec(item_ty)) = env.trace_type(ty).map(|t| t.as_ref().clone()) {
                mutate_vec(v, &item_ty, env, rng, depth);
            }
        }
        IDLValue::Principal(p) => mutate_principal(p, rng),
        IDLValue::Blob(items) => mutate_blob(items, rng),

        IDLValue::Record(fields) => {
            if let Ok(TypeInner::Record(field_types)) =
                env.trace_type(ty).map(|t| t.as_ref().clone())
            {
                if !fields.is_empty() {
                    let idx = rng.random_range(0..fields.len());
                    if let Some(field_ty) = field_types
                        .iter()
                        .find(|f| f.id == Rc::new(fields[idx].id.clone()))
                    {
                        mutate_value(&mut fields[idx].val, &field_ty.ty, env, rng, depth + 1);
                    }
                }
            }
        }
        IDLValue::Variant(v) => {
            if let Ok(TypeInner::Variant(variant_fields)) =
                env.trace_type(ty).map(|t| t.as_ref().clone())
            {
                if !variant_fields.is_empty() && rng.random_bool(0.2) {
                    // Switch to a different variant
                    let new_variant_idx = rng.random_range(0..variant_fields.len());
                    let new_field_type = &variant_fields[new_variant_idx];
                    let mut new_val = IDLValue::Null; // Placeholder
                    // Generate a new random value for the new variant
                    let seed = rng.random::<u64>().to_le_bytes().to_vec();
                    if let Ok(random_val) = candid_parser::random::any(
                        &seed,
                        Configs::from_str("").unwrap(),
                        env,
                        &[new_field_type.ty.clone()],
                        &None,
                    ) {
                        if !random_val.args.is_empty() {
                            new_val = random_val.args[0].clone();
                        }
                    }
                    v.0.id = Rc::into_inner(new_field_type.id.clone()).unwrap();
                    v.0.val = new_val;
                    v.1 = new_variant_idx as u64;
                } else {
                    // Mutate the value of the current variant
                    if let Some(field_ty) = variant_fields
                        .iter()
                        .find(|f| f.id == Rc::new(v.0.id.clone()))
                    {
                        mutate_value(&mut v.0.val, &field_ty.ty, env, rng, depth + 1);
                    }
                }
            }
        }

        IDLValue::Opt(o) => mutate_opt(o, ty, env, rng, depth),
        IDLValue::Service(_principal) => {
            unimplemented!("Mutating service defintion is umimplemented!")
        }
        IDLValue::Func(_principal, _) => {
            unimplemented!("Mutating func defintion is umimplemented!")
        }
    }
}

fn mutate_text<R: Rng>(s: &mut String, rng: &mut R) {
    match rng.random_range(0..10) {
        0..5 => {
            let idx = rng.random_range(0..s.len());
            let naughty_index = rng.random_range(0..naughty_strings::BLNS.len());
            s.insert_str(idx, naughty_strings::BLNS[naughty_index]);
        }
        5 => {
            if !s.is_empty() {
                s.pop();
            }
        }
        6 => *s = String::from(""),
        7..9 => {
            if !s.is_empty() {
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
    let val = &i.0;
    let new_val = match rng.random_range(0..20) {
        0 => val + 1,
        1 => val - 1,
        2 => BigInt::from(0),
        3 => BigInt::from(i64::MIN),
        4 => BigInt::from(i64::MAX),
        5..20 => {
            let random = BigInt::from(rng.random::<i128>());
            match rng.random_range(0..3) {
                0 => random + val,
                1 => random - val,
                2 => random * val,
                _ => val.clone(),
            }
        }
        _ => val.clone(),
    };
    *i = Int(new_val);
}

fn mutate_nat<R: Rng>(n: &mut Nat, rng: &mut R) {
    let val = &n.0;
    let new_val = match rng.random_range(0..20) {
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
        4..20 => {
            let random = BigUint::from(rng.random::<u128>());
            match rng.random_range(0..3) {
                0 => random + val,
                1 => random - val,
                2 => random * val,
                _ => val.clone(),
            }
        }
        _ => val.clone(),
    };
    *n = Nat(new_val);
}

fn mutate_float<F, R: Rng>(f: F, rng: &mut R) -> F
where
    F: num_traits::Float + Copy,
    StandardUniform: Distribution<F>,
{
    let random = rng.random::<F>();

    if rng.random_bool(0.05) {
        return F::nan();
    }
    if rng.random_bool(0.05) {
        return F::infinity();
    }

    match rng.random_range(0..3) {
        0 => random + f,
        1 => random - f,
        2 => random * f,
        _ => f,
    }
}

fn mutate_vec<R: Rng>(
    vec: &mut Vec<IDLValue>,
    item_ty: &Type,
    env: &TypeEnv,
    rng: &mut R,
    depth: usize,
) {
    if vec.is_empty() {
        return;
    }

    match rng.random_range(0..3) {
        0 => {
            let idx = rng.random_range(0..vec.len());
            vec.remove(idx);
        }
        1 => {
            let length = vec.len();
            let idx = rng.random_range(0..length);
            let val = vec[idx].clone();
            vec.push(val);
            mutate_value(&mut vec[length], item_ty, env, rng, depth + 1);
        }
        2 => {
            let idx = rng.random_range(0..vec.len());
            mutate_value(&mut vec[idx], item_ty, env, rng, depth + 1);
        }
        _ => {}
    }
}

fn mutate_principal<R: Rng>(p: &mut Principal, rng: &mut R) {
    *p = match rng.random::<u8>() {
        u8::MAX => Principal::management_canister(),
        254u8 => Principal::anonymous(),
        _ => {
            let length: usize = rng.random_range(1..=Principal::MAX_LENGTH_IN_BYTES);
            let mut result: Vec<u8> = Vec::with_capacity(length);
            for _ in 0..length {
                result.push(rng.random::<u8>());
            }
            let last = result.last_mut().unwrap();
            // Anonymous tag
            if *last == 4 {
                *last = u8::MAX
            }
            Principal::try_from(&result[..]).unwrap()
        }
    }
}

fn mutate_blob<R: Rng>(b: &mut Vec<u8>, rng: &mut R) {
    let new_size = rng.random_range(0..b.len());
    b.resize(new_size, 0);
    rng.fill_bytes(b);
}

fn mutate_primitive<T, R>(val: T, rng: &mut R) -> T
where
    T: PrimInt + WrappingAdd + WrappingSub + WrappingMul,
    StandardUniform: Distribution<T>,
    R: Rng,
{
    let random = rng.random::<T>();

    match rng.random_range(0..4) {
        0 => random.wrapping_add(&val),
        1 => random.wrapping_sub(&val),
        2 => random.wrapping_mul(&val),
        3 => random ^ val,
        _ => val,
    }
}

fn mutate_opt<R: Rng>(o: &mut Box<IDLValue>, ty: &Type, env: &TypeEnv, rng: &mut R, depth: usize) {
    if let Ok(TypeInner::Opt(inner_ty)) = env.trace_type(ty).map(|t| t.as_ref().clone()) {
        mutate_value(o, &inner_ty, env, rng, depth);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::types::value::VariantValue;
    use candid::types::{Field, Label};
    use rand::SeedableRng;
    use std::rc::Rc;

    const STATIC_SEED: u64 = 7355608;

    #[test]
    fn test_mutate_text() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut s = "hello".to_string();
        mutate_text(&mut s, &mut rng);
        assert_eq!(
            s,
            "h\"`'><script>\\xE3\\x80\\x80javascript:alert(1)</script>ello"
        );
    }

    #[test]
    fn test_mutate_int() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut i = Int(BigInt::from(100));
        mutate_int(&mut i, &mut rng);
        assert_eq!(i, Int(BigInt::from(0)));
    }

    #[test]
    fn test_mutate_nat() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut n = Nat(BigUint::from(100u32));
        mutate_nat(&mut n, &mut rng);
        assert_eq!(n, Nat(BigUint::from(18446744073709551615u64)));
    }

    #[test]
    fn test_mutate_float() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let f: f64 = 123.456;
        let mutated_f = mutate_float(f, &mut rng);
        assert_eq!(mutated_f, f64::INFINITY);
    }

    #[test]
    fn test_mutate_primitive() {
        macro_rules! test_primitive {
            ($ty:ty, $val:expr, $expected:expr) => {
                let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
                let val: $ty = $val;
                let mutated = mutate_primitive(val, &mut rng);
                assert_eq!(mutated, $expected, "failed for type {}", stringify!($ty));
            };
        }

        test_primitive!(i8, 10, 36);
        test_primitive!(i16, 10, -26844);
        test_primitive!(i32, 10, 541693732);
        test_primitive!(i64, 10, -1227287045443950644_i64);
        test_primitive!(u8, 10, 36);
        test_primitive!(u16, 10, 38692);
        test_primitive!(u32, 10, 541693732_u32);
        test_primitive!(u64, 10, 17219457028265600972u64);
    }

    #[test]
    fn test_mutate_principal() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut p = Principal::anonymous();
        mutate_principal(&mut p, &mut rng);
        // Generates a new random principal
        let expected =
            Principal::try_from(&[197, 8, 228, 253, 44, 55, 230, 45, 210, 76, 14, 52][..]).unwrap();
        assert_eq!(p, expected);
    }

    #[test]
    fn test_mutate_blob() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut b = vec![1, 2, 3, 4, 5];
        mutate_blob(&mut b, &mut rng);
        assert_eq!(b, Vec::<u8>::new());
    }

    #[test]
    fn test_mutate_vec() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut v = vec![IDLValue::Nat8(10), IDLValue::Nat8(20)];
        let item_ty = TypeInner::Nat8.into();
        let env = TypeEnv::new();
        mutate_vec(&mut v, &item_ty, &env, &mut rng, 0);
        assert_eq!(v, vec![IDLValue::Nat8(20)]);
    }

    #[test]
    fn test_mutate_opt() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut opt_val = Box::new(IDLValue::Nat8(10));
        let ty = TypeInner::Opt(TypeInner::Nat8.into()).into();
        let env = TypeEnv::new();
        mutate_opt(&mut opt_val, &ty, &env, &mut rng, 0);
        // Mutates the inner value
        assert_eq!(*opt_val, IDLValue::Nat8(36));
    }

    #[test]
    fn test_mutate_record() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut val = IDLValue::Record(vec![
            candid::types::value::IDLField {
                id: Label::Named("a".to_string()),
                val: IDLValue::Nat8(10),
            },
            candid::types::value::IDLField {
                id: Label::Named("b".to_string()),
                val: IDLValue::Bool(true),
            },
        ]);
        let ty: Type = TypeInner::Record(vec![
            Field {
                id: Rc::new(Label::Named("a".to_string())),
                ty: TypeInner::Nat8.into(),
            },
            Field {
                id: Rc::new(Label::Named("b".to_string())),
                ty: TypeInner::Bool.into(),
            },
        ])
        .into();
        let env = TypeEnv::new();

        mutate_value(&mut val, &ty, &env, &mut rng, 0);

        // Mutates the first field
        let expected = IDLValue::Record(vec![
            candid::types::value::IDLField {
                id: Label::Named("a".to_string()),
                val: IDLValue::Nat8(238),
            },
            candid::types::value::IDLField {
                id: Label::Named("b".to_string()),
                val: IDLValue::Bool(true),
            },
        ]);
        assert_eq!(val, expected);
    }

    #[test]
    fn test_mutate_variant_value() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(STATIC_SEED);
        let mut val = IDLValue::Variant(VariantValue(
            Box::new(candid::types::value::IDLField {
                id: Label::Named("A".to_string()),
                val: IDLValue::Nat8(10),
            }),
            0,
        ));
        let ty: Type = TypeInner::Variant(vec![
            Field {
                id: Rc::new(Label::Named("A".to_string())),
                ty: TypeInner::Nat8.into(),
            },
            Field {
                id: Rc::new(Label::Named("B".to_string())),
                ty: TypeInner::Bool.into(),
            },
        ])
        .into();
        let env = TypeEnv::new();

        mutate_value(&mut val, &ty, &env, &mut rng, 0);

        let expected = IDLValue::Variant(VariantValue(
            Box::new(candid::types::value::IDLField {
                id: Label::Named("A".to_string()),
                val: IDLValue::Nat8(207),
            }),
            0,
        ));
        assert_eq!(val, expected);
    }
}
