use crate::crypto::merkle_tree::blake3::{self as mt, MerkleTreeParams};
use crate::parameters::{
    default_max_pow, FoldType, MultivariateParameters, SoundnessType, WhirParameters,
};
use crate::poly_utils::coeffs::CoefficientList;
use crate::whir::{
    committer::{Committer, Witness},
    iopattern::WhirIOPattern,
    parameters::WhirConfig,
    Error, PolynomialCommitmentScheme, WhirProof,
};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nimue::{DefaultHash, IOPattern};
use nimue_pow::blake3::Blake3PoW;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct Whir<E>(PhantomData<E>);

type MerkleConfig<E> = MerkleTreeParams<E>;
type PowStrategy = Blake3PoW;
type WhirPCSConfig<E> = WhirConfig<E, MerkleConfig<E>, PowStrategy>;

impl<E> PolynomialCommitmentScheme<E> for Whir<E>
where
    E: FftField + CanonicalSerialize + CanonicalDeserialize,
{
    type Param = WhirPCSConfig<E>;
    type ProverParam = WhirPCSConfig<E>;
    type VerifierParam = WhirPCSConfig<E>;
    type CommitmentWithData = Witness<E, MerkleTreeParams<E>>;
    type Proof = WhirProof<MerkleTreeParams<E>, E>;
    // TODO: support both base and extension fields
    type Poly = CoefficientList<E::BasePrimeField>;
    type Transcript = IOPattern<DefaultHash>;

    fn setup(poly_size: usize) -> Self::Param {
        let mv_params = MultivariateParameters::<E>::new(poly_size);
        let starting_rate = 1;
        let pow_bits = default_max_pow(poly_size, starting_rate);
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

        let (leaf_hash_params, two_to_one_params) = mt::default_config::<E>(&mut rng);

        let whir_params = WhirParameters::<MerkleConfig<E>, PowStrategy> {
            initial_statement: true,
            security_level: 100,
            pow_bits,
            folding_factor: 4,
            leaf_hash_params,
            two_to_one_params,
            soundness_type: SoundnessType::ConjectureList,
            fold_optimisation: FoldType::ProverHelps,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: starting_rate,
        };
        WhirConfig::<E, MerkleConfig<E>, PowStrategy>::new(mv_params, whir_params)
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &Self::Poly,
    ) -> Result<Self::CommitmentWithData, Error> {
        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);

        let mut merlin = io.to_merlin();
        let committer = Committer::new(pp.clone());
        let witness = committer.commit(&mut merlin, poly.clone()).unwrap();
        Ok(witness)
    }

    fn batch_commit(
        _pp: &Self::ProverParam,
        _polys: &[Self::Poly],
    ) -> Result<Self::CommitmentWithData, Error> {
        todo!()
    }

    fn open(
        _pp: &Self::ProverParam,
        _poly: &Self::Poly,
        _comm: &Self::CommitmentWithData,
        _point: &[E],
        _eval: &E,
        _transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        todo!()
    }

    fn batch_open(
        _pp: &Self::ProverParam,
        _polys: &[Self::Poly],
        _comm: &Self::CommitmentWithData,
        _point: &[E],
        _evals: &[E],
        _transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        todo!()
    }

    fn verify(
        _vp: &Self::VerifierParam,
        _point: &[E],
        _eval: &E,
        _proof: &Self::Proof,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }

    fn batch_verify(
        _vp: &Self::VerifierParam,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }
}
