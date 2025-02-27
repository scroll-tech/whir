use std::fs::read;

use crate::whir::{Statement, WhirProof};
use crate::crypto::fields::Field64;
use ark_ff::BigInteger;
use ark_ff::fields::PrimeField as ArkPrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::merkle_tree::Config as ArkConfig;
use crate::poly_utils::MultilinearPoint;
use openvm_native_recursion::hints::{Hintable, VecAutoHintable, InnerVal, InnerChallenge};
use openvm_native_compiler::{
    prelude::*,
    ir::{Config, Builder, Array, Felt},
    asm::AsmConfig,
};
use openvm_stark_backend::p3_field::{Field as Plonky3Field, extension::BinomialExtensionField, FieldAlgebra, FieldExtensionAlgebra};
pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;

fn to_bigint_u64(n: Field64) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&n.into_bigint().to_bytes_le());
    u64::from_le_bytes(bytes)
}

#[derive(DslVariable, Clone)]
pub struct MultilinearPointVariable<C: Config> {
    pub points: Array<C, Felt<C::F>>
}

impl Hintable<InnerConfig> for MultilinearPoint<Field64> {
    type HintVariable = MultilinearPointVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let points = builder.hint_felts();
        Self::HintVariable {
            points
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        
        let pts = self.0.iter().map(|p| {
            <InnerConfig as Config>::N::from_wrapped_u64(to_bigint_u64(*p))
        }).collect::<Vec<<InnerConfig as Config>::N>>();

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

        let evals = self.evaluations.iter().map(|e| {
            <InnerConfig as Config>::N::from_wrapped_u64(to_bigint_u64(*e))
        }).collect::<Vec<<InnerConfig as Config>::N>>();
        stream.extend(evals.write());
        stream
    }
}