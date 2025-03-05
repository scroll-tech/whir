use crate::crypto::fields::Field64;
use crate::crypto::merkle_tree::blake3::{self as merkle_tree, Blake3Digest};
use crate::poly_utils::MultilinearPoint;
use crate::whir::{Statement, WhirProof};
use ark_ff::fields::PrimeField as ArkPrimeField;
use ark_ff::BigInteger;
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config, Felt},
    prelude::*,
};
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::hints::{Hintable, InnerChallenge, InnerVal, VecAutoHintable};
use openvm_stark_backend::p3_field::FieldAlgebra;

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;
type MerkleConfig = merkle_tree::MerkleTreeParams<Field64>;

fn to_bigint_u64(n: Field64) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&n.into_bigint().to_bytes_le());
    u64::from_le_bytes(bytes)
}

#[derive(DslVariable, Clone)]
pub struct MultilinearPointVariable<C: Config> {
    pub points: Array<C, Felt<C::F>>,
}

impl Hintable<InnerConfig> for MultilinearPoint<Field64> {
    type HintVariable = MultilinearPointVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let points = builder.hint_felts();
        Self::HintVariable { points }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();

        let pts = self
            .0
            .iter()
            .map(|p| <InnerConfig as Config>::N::from_wrapped_u64(to_bigint_u64(*p)))
            .collect::<Vec<<InnerConfig as Config>::N>>();

        stream.extend(pts.write());
        stream
    }
}

impl VecAutoHintable for MultilinearPoint<Field64> {}

#[derive(DslVariable, Clone)]
pub struct StatementVariable<C: Config> {
    pub points: Array<C, MultilinearPointVariable<C>>,
    pub evaluations: Array<C, Felt<C::F>>,
}

impl Hintable<InnerConfig> for Statement<Field64> {
    type HintVariable = StatementVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let points = Vec::<MultilinearPoint<Field64>>::read(builder);
        let evaluations = builder.hint_felts();
        Self::HintVariable {
            points,
            evaluations,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.points.write());

        let evals = self
            .evaluations
            .iter()
            .map(|e| <InnerConfig as Config>::N::from_wrapped_u64(to_bigint_u64(*e)))
            .collect::<Vec<<InnerConfig as Config>::N>>();
        stream.extend(evals.write());
        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct WhirProofVariable<C: Config> {
    pub len: Usize<C::N>,
    pub proofs: Array<C, WhirProofRoundVariable<C>>,
}

#[derive(DslVariable, Clone)]
pub struct WhirProofRoundVariable<C: Config> {
    pub leaf_siblings_hashes: Array<C, BlakeDigestVariable<C>>,
    pub auth_paths_prefix_lengths: Array<C, Var<C::N>>,
    pub suffix_len: Usize<C::N>,
    pub auth_paths_suffixes: Array<C, Array<C, BlakeDigestVariable<C>>>,
    pub leaf_indexes: Array<C, Var<C::N>>,
    pub answers_len: Usize<C::N>,
    pub answers: Array<C, Array<C, Felt<C::F>>>,
}

#[derive(DslVariable, Clone)]
pub struct BlakeDigestVariable<C: Config> {
    pub digest: Array<C, Felt<C::F>>,
}

impl Hintable<InnerConfig> for Blake3Digest {
    type HintVariable = BlakeDigestVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        Self::HintVariable {
            digest: builder.hint_felts(),
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        let bytes = self
            .as_ref()
            .iter()
            .map(|b| <InnerConfig as Config>::N::from_canonical_u8(*b))
            .collect::<Vec<<InnerConfig as Config>::N>>();
        stream.extend(bytes.write());
        stream
    }
}
impl VecAutoHintable for Blake3Digest {}

impl Hintable<InnerConfig> for WhirProof<MerkleConfig, Field64> {
    type HintVariable = WhirProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let len = Usize::Var(usize::read(builder));
        let proofs = builder.dyn_array(len.clone());

        iter_zip!(builder, proofs).for_each(|idx_vec, builder| {
            let ptr = idx_vec[0];

            let leaf_siblings_hashes = Vec::<Blake3Digest>::read(builder);
            let auth_paths_prefix_lengths = Vec::<usize>::read(builder);
            let suffix_len = Usize::Var(usize::read(builder));
            let auth_paths_suffixes = builder.dyn_array(suffix_len.clone());
            iter_zip!(builder, auth_paths_suffixes).for_each(|suffix_idx_vec, builder| {
                let sfx_ptr = suffix_idx_vec[0];
                let suffix_digests = Vec::<Blake3Digest>::read(builder);
                builder.iter_ptr_set(&auth_paths_suffixes, sfx_ptr, suffix_digests);
            });
            let leaf_indexes = Vec::<usize>::read(builder);
            let answers_len = Usize::Var(usize::read(builder));
            let answers = builder.dyn_array(answers_len.clone());
            iter_zip!(builder, answers).for_each(|answers_idx_vec, builder| {
                let answer_ptr = answers_idx_vec[0];
                let v = builder.hint_felts();
                builder.iter_ptr_set(&answers, answer_ptr, v);
            });

            builder.iter_ptr_set(
                &proofs,
                ptr,
                WhirProofRoundVariable {
                    leaf_siblings_hashes,
                    auth_paths_prefix_lengths,
                    suffix_len,
                    auth_paths_suffixes,
                    leaf_indexes,
                    answers_len,
                    answers,
                },
            )
        });

        Self::HintVariable { len, proofs }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();

        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.0.len()));

        for round in self.0.iter() {
            stream.extend(round.0.leaf_siblings_hashes.write());
            stream.extend(round.0.auth_paths_prefix_lenghts.write());
            stream.extend(<usize as Hintable<InnerConfig>>::write(
                &round.0.auth_paths_suffixes.len(),
            ));
            for suffix in round.0.auth_paths_suffixes.iter() {
                stream.extend(suffix.write());
            }
            stream.extend(round.0.leaf_indexes.write());
            stream.extend(<usize as Hintable<InnerConfig>>::write(&round.1.len()));
            for v in round.1.iter() {
                let answers = v
                    .iter()
                    .map(|a| <InnerConfig as Config>::N::from_wrapped_u64(to_bigint_u64(*a)))
                    .collect::<Vec<<InnerConfig as Config>::N>>();
                stream.extend(answers.write());
            }
        }

        stream
    }
}
