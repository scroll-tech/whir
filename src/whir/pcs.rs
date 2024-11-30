use crate::crypto::merkle_tree::blake3::MerkleTreeParams;
use crate::poly_utils::coeffs::CoefficientList;
use crate::whir::{
    committer::Witness, parameters::WhirConfig, Error, PolynomialCommitmentScheme, WhirProof,
};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nimue::{DefaultHash, IOPattern};
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct Whir<E>(PhantomData<E>);

type WhirPCSConfig<E> = WhirConfig<E, MerkleTreeParams<E>, ()>;

impl<E> PolynomialCommitmentScheme<E> for Whir<E>
where
    E: FftField + CanonicalSerialize + CanonicalDeserialize,
{
    type Param = WhirPCSConfig<E>;
    type ProverParam = WhirPCSConfig<E>;
    type VerifierParam = WhirPCSConfig<E>;
    type CommitmentWithData = Witness<E, MerkleTreeParams<E>>;
    type Proof = WhirProof<MerkleTreeParams<E>, E>;
    type Poly = CoefficientList<E>;
    type Transcript = IOPattern<DefaultHash>;

    fn setup(_poly_size: usize) -> Result<Self::Param, Error> {
        todo!()
    }

    fn commit(
        _pp: &Self::ProverParam,
        _poly: &Self::Poly,
    ) -> Result<Self::CommitmentWithData, Error> {
        todo!()
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
