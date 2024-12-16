use super::{Error, PolynomialCommitmentScheme};
use crate::crypto::merkle_tree::blake3::{self as mt, MerkleTreeParams};
use crate::parameters::{
    default_max_pow, FoldType, MultivariateParameters, SoundnessType, WhirParameters,
};
use crate::poly_utils::{coeffs::CoefficientList, MultilinearPoint};
use crate::whir::fs_utils::{DigestReader, DigestWriter};
use crate::whir::{
    committer::{Committer, Witness},
    iopattern::WhirIOPattern,
    parameters::WhirConfig,
    prover::Prover,
    verifier::Verifier,
    Statement, WhirProof,
};

use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use core::num;
use nimue::{Arthur, DefaultHash, IOPattern, Merlin};
use nimue_pow::blake3::Blake3PoW;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
#[cfg(feature = "parallel")]
use rayon::slice::ParallelSlice;
use serde::ser::SerializeStruct;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

type PowStrategy = Blake3PoW;
// type WhirPCSConfig<E> = WhirConfig<E, MerkleTreeParams<E>, PowStrategy>;

pub trait WhirSpec<E: FftField>: Clone {
    type MerkleConfig: Config<Leaf = [E]> + Clone;
    // where
    //     Merlin: DigestWriter<Self::MerkleConfig>,
    //     IOPattern: WhirIOPattern<E, Self::MerkleConfig>;
    fn get_parameters(num_variables: usize) -> WhirParameters<Self::MerkleConfig, PowStrategy>;
}

#[derive(Debug, Clone)]
pub struct WhirDefaultSpec;

impl<E: FftField> WhirSpec<E> for WhirDefaultSpec {
    type MerkleConfig = MerkleTreeParams<E>;
    fn get_parameters(num_variables: usize) -> WhirParameters<Self::MerkleConfig, PowStrategy> {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let (leaf_hash_params, two_to_one_params) = mt::default_config::<E>(&mut rng);
        WhirParameters::<Self::MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 100,
            pow_bits: default_max_pow(num_variables, 1),
            folding_factor: 4,
            leaf_hash_params,
            two_to_one_params,
            soundness_type: SoundnessType::ConjectureList,
            fold_optimisation: FoldType::ProverHelps,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhirSetupParams<E: FftField> {
    pub num_variables: usize,
    _phantom: PhantomData<E>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Whir<E: FftField, Spec: WhirSpec<E>>(PhantomData<(E, Spec)>);

// Wrapper for WhirProof
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WhirProofWrapper<MerkleConfig, F>(WhirProof<MerkleConfig, F>)
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize;

impl<MerkleConfig, F> Serialize for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let proof = &self.0 .0;
        // Create a buffer that implements the `Write` trait
        let mut buffer = Vec::new();
        proof.serialize_compressed(&mut buffer).unwrap();
        serializer.serialize_bytes(&buffer)
    }
}

impl<'de, MerkleConfig, F> Deserialize<'de> for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize the bytes into a buffer
        let buffer: Vec<u8> = Deserialize::deserialize(deserializer)?;
        // Deserialize the buffer into a proof
        let proof = WhirProof::deserialize_compressed(&buffer[..]).unwrap();
        Ok(WhirProofWrapper(proof))
    }
}

impl<E, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: FftField + CanonicalSerialize + CanonicalDeserialize + Serialize + DeserializeOwned + Debug,
    E::BasePrimeField: Serialize + DeserializeOwned + Debug,
    Merlin: DigestWriter<Spec::MerkleConfig>,
    for<'a> Arthur<'a>: DigestReader<Spec::MerkleConfig>,
    IOPattern: WhirIOPattern<E, Spec::MerkleConfig>,
{
    type Param = WhirSetupParams<E>;
    type CommitmentWithWitness = Witness<E, Spec::MerkleConfig>;
    type Proof = WhirProofWrapper<Spec::MerkleConfig, E>;
    type Poly = CoefficientList<E::BasePrimeField>;
    type Transcript = Merlin<DefaultHash>;

    fn setup(poly_size: usize) -> Self::Param {
        WhirSetupParams {
            num_variables: log2(poly_size) as usize,
            _phantom: PhantomData,
        }
    }

    fn commit_and_write(
        pp: &Self::Param,
        poly: &Self::Poly,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let whir_params = Spec::get_parameters(pp.num_variables);
        let mv_params = MultivariateParameters::new(pp.num_variables);
        let params = WhirConfig::<E, Spec::MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let committer = Committer::new(params);
        let witness = committer.commit(transcript, poly.clone())?;

        Ok(witness)
    }

    fn batch_commit(
        _pp: &Self::Param,
        _polys: &[Self::Poly],
    ) -> Result<Self::CommitmentWithWitness, Error> {
        todo!()
    }

    fn open(
        pp: &Self::Param,
        witness: Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        let whir_params = Spec::get_parameters(pp.num_variables);
        let mv_params = MultivariateParameters::new(pp.num_variables);
        let params = WhirConfig::<E, Spec::MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let prover = Prover(params);
        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let proof = prover.prove(transcript, statement, witness)?;
        Ok(WhirProofWrapper(proof))
    }

    fn batch_open(
        _pp: &Self::Param,
        _polys: &[Self::Poly],
        _comm: Self::CommitmentWithWitness,
        _point: &[E],
        _evals: &[E],
        _transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        todo!()
    }

    fn verify(
        vp: &Self::Param,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &Self::Transcript,
    ) -> Result<(), Error> {
        let whir_params = Spec::get_parameters(vp.num_variables);
        let mv_params = MultivariateParameters::new(vp.num_variables);
        let params = WhirConfig::<E, Spec::MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let reps = 1000;
        let verifier = Verifier::new(params.clone());
        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&params)
            .add_whir_proof(&params);

        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        for _ in 0..reps {
            let mut arthur = io.to_arthur(transcript.transcript());
            verifier.verify(&mut arthur, &statement, &proof.0)?;
        }
        Ok(())
    }

    fn batch_verify(
        _vp: &Self::Param,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{Field, Fp2, MontBackend, MontConfig};
    use rand::Rng;

    use crate::crypto::fields::F2Config64;

    use super::*;

    type Field64_2 = Fp2<F2Config64>;

    type F = Field64_2;

    #[test]
    fn single_point_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        let pp = Whir::<F, WhirDefaultSpec>::setup(poly_size);

        let poly = CoefficientList::new(
            (0..num_coeffs)
                .map(<F as Field>::BasePrimeField::from)
                .collect(),
        );

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);
        let mut merlin = io.to_merlin();

        let witness = Whir::<F, Spec>::commit_and_write(&pp, &poly, &mut merlin).unwrap();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&MultilinearPoint(point.clone()));

        let proof = Whir::<F, Spec>::open(&pp, witness, &point, &eval, &mut merlin).unwrap();
        Whir::<F, Spec>::verify(&pp, &point, &eval, &proof, &merlin).unwrap();
    }
}
