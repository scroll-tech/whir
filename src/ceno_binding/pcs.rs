use super::merkle_config::{Blake3ConfigWrapper, WhirMerkleConfigWrapper};
use super::{Error, PolynomialCommitmentScheme};
use crate::crypto::merkle_tree::blake3::{self as mt};
use crate::parameters::{
    default_max_pow, FoldType, MultivariateParameters, SoundnessType, WhirParameters,
};
use crate::poly_utils::{coeffs::CoefficientList, MultilinearPoint};
use crate::whir::{
    committer::{Committer, Witness},
    parameters::WhirConfig,
    prover::Prover,
    verifier::Verifier,
    Statement, WhirProof,
};

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
pub use nimue::{Arthur, DefaultHash, Merlin};
use nimue::{IOPattern, ProofResult};
use nimue_pow::blake3::Blake3PoW;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

pub type PowStrategy = Blake3PoW;
// type WhirPCSConfig<E> = WhirConfig<E, MerkleTreeParams<E>, PowStrategy>;

pub trait WhirSpec<E: FftField>: Default + std::fmt::Debug + Clone {
    type MerkleConfigWrapper: WhirMerkleConfigWrapper<E>;
    fn get_parameters(
        num_variables: usize,
    ) -> WhirParameters<MerkleConfigOf<Self, E>, PowOf<Self, E>>;

    fn prepare_io_pattern(num_variables: usize) -> IOPattern {
        let whir_params = Self::get_parameters(num_variables);
        let mv_params = MultivariateParameters::new(num_variables);
        let params = ConfigOf::<Self, E>::new(mv_params, whir_params);

        let io = IOPattern::<DefaultHash>::new("🌪️");
        let io = commit_statement_to_io_pattern::<E, Self>(io, &params);
        let io = add_whir_proof_to_io_pattern::<E, Self>(io, &params);

        io
    }
}

pub type MerkleConfigOf<Spec, E> =
    <<Spec as WhirSpec<E>>::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::MerkleConfig;
type ConfigOf<Spec, E> = WhirConfig<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>;

pub fn commit_statement_to_io_pattern<E: FftField, Spec: WhirSpec<E>>(
    iopattern: IOPattern,
    params: &WhirConfig<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>,
) -> IOPattern {
    <Spec::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::commit_statement_to_io_pattern(
        iopattern, params,
    )
}

pub fn add_whir_proof_to_io_pattern<E: FftField, Spec: WhirSpec<E>>(
    iopattern: IOPattern,
    params: &WhirConfig<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>,
) -> IOPattern {
    <Spec::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_whir_proof_to_io_pattern(
        iopattern, params,
    )
}

pub fn add_digest_to_merlin<E: FftField, Spec: WhirSpec<E>>(
    merlin: &mut Merlin,
    digest: InnerDigestOf<Spec, E>,
) -> ProofResult<()> {
    <Spec::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_digest_to_merlin(merlin, digest)
}

pub type InnerDigestOf<Spec, E> = <MerkleConfigOf<Spec, E> as Config>::InnerDigest;

pub type PowOf<Spec, E> =
    <<Spec as WhirSpec<E>>::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::PowStrategy;

#[derive(Debug, Clone, Default)]
pub struct WhirDefaultSpec;

impl<E: FftField> WhirSpec<E> for WhirDefaultSpec {
    type MerkleConfigWrapper = Blake3ConfigWrapper<E>;
    fn get_parameters(
        num_variables: usize,
    ) -> WhirParameters<MerkleConfigOf<Self, E>, PowStrategy> {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let (leaf_hash_params, two_to_one_params) = mt::default_config::<E>(&mut rng);
        WhirParameters::<MerkleConfigOf<Self, E>, PowStrategy> {
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
pub struct WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    pub proof: WhirProof<MerkleConfig, F>,
    pub transcript: Vec<u8>,
}

impl<MerkleConfig, F> Serialize for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let proof = &self.proof.0;
        // Create a buffer that implements the `Write` trait
        let mut buffer = Vec::new();
        proof.serialize_compressed(&mut buffer).unwrap();
        let proof_size = buffer.len();
        let proof_size_bytes = proof_size.to_le_bytes();
        let mut data = proof_size_bytes.to_vec();
        data.extend_from_slice(&buffer);
        data.extend_from_slice(&self.transcript);
        serializer.serialize_bytes(&data)
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
        let data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let proof_size_bytes = &data[0..8];
        let proof_size = u64::from_le_bytes(proof_size_bytes.try_into().unwrap());
        let proof_bytes = &data[8..8 + proof_size as usize];
        let proof = WhirProof::deserialize_compressed(&proof_bytes[..]).unwrap();
        let transcript = data[8 + proof_size as usize..].to_vec();
        Ok(WhirProofWrapper { proof, transcript })
    }
}

impl<MerkleConfig, F> Debug for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("WhirProofWrapper")
    }
}

#[derive(Clone)]
pub struct CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    pub commitment: MerkleConfig::InnerDigest,
    pub witness: Witness<F, MerkleConfig>,
}

impl<F: FftField, MerkleConfig> CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    pub fn ood_answers(&self) -> Vec<F> {
        self.witness.ood_answers.clone()
    }
}

impl<F, MerkleConfig> Debug for CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("CommitmentWithWitness")
    }
}

impl<E, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: FftField + Serialize + DeserializeOwned + Debug,
    E::BasePrimeField: Serialize + DeserializeOwned + Debug,
{
    type Param = WhirSetupParams<E>;
    type Commitment = <MerkleConfigOf<Spec, E> as Config>::InnerDigest;
    type CommitmentWithWitness = CommitmentWithWitness<E, MerkleConfigOf<Spec, E>>;
    type Proof = WhirProofWrapper<MerkleConfigOf<Spec, E>, E>;
    type Poly = CoefficientList<E::BasePrimeField>;

    fn setup(poly_size: usize) -> Self::Param {
        WhirSetupParams {
            num_variables: log2(poly_size) as usize,
            _phantom: PhantomData,
        }
    }

    fn commit_and_write(
        pp: &Self::Param,
        poly: &Self::Poly,
        merlin: &mut Merlin<DefaultHash>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let whir_params = Spec::get_parameters(pp.num_variables);
        let mv_params = MultivariateParameters::new(pp.num_variables);
        let params =
            WhirConfig::<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>::new(mv_params, whir_params);

        let committer = Committer::new(params);
        let witness =
            Spec::MerkleConfigWrapper::commit_to_merlin(&committer, merlin, poly.clone())?;

        Ok(CommitmentWithWitness {
            commitment: witness.merkle_tree.root(),
            witness,
        })
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
        merlin: &mut Merlin<DefaultHash>,
    ) -> Result<Self::Proof, Error> {
        let whir_params = Spec::get_parameters(pp.num_variables);
        let mv_params = MultivariateParameters::new(pp.num_variables);
        let params =
            WhirConfig::<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>::new(mv_params, whir_params);

        let prover = Prover(params);
        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let proof = Spec::MerkleConfigWrapper::prove_with_merlin(
            &prover,
            merlin,
            statement,
            witness.witness,
        )?;

        Ok(WhirProofWrapper {
            proof,
            transcript: merlin.transcript().to_vec(),
        })
    }

    fn batch_open(
        _pp: &Self::Param,
        _polys: &[Self::Poly],
        _comm: Self::CommitmentWithWitness,
        _point: &[E],
        _evals: &[E],
        _transcript: &mut Merlin<DefaultHash>,
    ) -> Result<Self::Proof, Error> {
        todo!()
    }

    fn verify(
        vp: &Self::Param,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        arthur: &mut Arthur<DefaultHash>,
    ) -> Result<(), Error> {
        let whir_params = Spec::get_parameters(vp.num_variables);
        let mv_params = MultivariateParameters::new(vp.num_variables);
        let params =
            WhirConfig::<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>::new(mv_params, whir_params);

        let verifier = Verifier::new(params.clone());

        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let digest = Spec::MerkleConfigWrapper::verify_with_arthur(
            &verifier,
            arthur,
            &statement,
            &proof.proof,
        )?;

        if &digest != comm {
            return Err(Error::CommitmentMismatchFromDigest);
        }

        Ok(())
    }

    fn batch_verify(
        _vp: &Self::Param,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut Arthur<DefaultHash>,
    ) -> Result<(), Error> {
        todo!()
    }
}
