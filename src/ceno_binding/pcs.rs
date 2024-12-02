use super::error::Error;
use super::PolynomialCommitmentScheme;
use crate::crypto::merkle_tree::blake3::{CompressH, MerkleTreeParams};
use crate::whir::committer::Witness;
use crate::whir::parameters::WhirConfig;
use crate::whir::WhirProof;

use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
    type Commitment = <CompressH as TwoToOneCRHScheme>::Output;
    type CommitmentChunk = <CompressH as TwoToOneCRHScheme>::Output;
    type Proof = WhirProof<MerkleTreeParams<E>, E>;
    type Poly = ();
    type Transcript = ();

    fn setup(_poly_size: usize) -> Result<Self::Param, Error> {
        todo!()
    }

    fn commit(
        _pp: &Self::ProverParam,
        _poly: &Self::Poly,
    ) -> Result<Self::CommitmentWithData, Error> {
        todo!()
    }

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Poly,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn write_commitment(
        _comm: &Self::Commitment,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }

    fn get_pure_commitment(_comm: &Self::CommitmentWithData) -> Self::Commitment {
        todo!()
    }

    fn batch_commit(
        _pp: &Self::ProverParam,
        _polys: &[Self::Poly],
    ) -> Result<Self::CommitmentWithData, Error> {
        todo!()
    }

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[Self::Poly],
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::batch_commit(pp, polys)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
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
        _comm: &Self::Commitment,
        _point: &[E],
        _eval: &E,
        _proof: &Self::Proof,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }

    fn batch_verify(
        _vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut Self::Transcript,
    ) -> Result<(), Error> {
        todo!()
    }
}
