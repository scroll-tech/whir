pub mod pcs;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::Debug;

use crate::parameters::WhirPartialParameters;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ProofError(#[from] nimue::ProofError),
    #[error("InvalidPcsParams")]
    InvalidPcsParam,
}

pub trait PolynomialCommitmentScheme<E: FftField>: Clone {
    type Param: Clone;
    type CommitmentWithWitness;
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;
    type Poly: Clone;
    type Transcript;

    fn setup(
        poly_size: usize,
        num_polys: usize,
        params: Option<WhirPartialParameters>,
    ) -> Self::Param;

    fn commit_and_write(
        pp: &Self::Param,
        poly: &Self::Poly,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn batch_commit_and_write(
        pp: &Self::Param,
        polys: &[Self::Poly],
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn open(
        pp: &Self::Param,
        comm: Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error>;

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::Param,
        comm: Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        vp: &Self::Param,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &Self::Transcript,
    ) -> Result<(), Error>;

    fn simple_batch_verify(
        vp: &Self::Param,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &Self::Transcript,
    ) -> Result<(), Error>;
}
