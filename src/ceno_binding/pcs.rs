use super::{Error, PolynomialCommitmentScheme};
use crate::crypto::merkle_tree::blake3::{self as mt, MerkleTreeParams};
use crate::parameters::{
    default_max_pow, FoldType, MultivariateParameters, SoundnessType, WhirParameters,
};
use crate::poly_utils::{coeffs::CoefficientList, MultilinearPoint};
use crate::whir::{
    committer::{Committer, Witnesses},
    iopattern::WhirIOPattern,
    parameters::WhirConfig,
    prover::Prover,
    verifier::Verifier,
    Statement, WhirProof,
};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nimue::{DefaultHash, IOPattern, Merlin};
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
    type CommitmentWithWitness = Witnesses<E, MerkleTreeParams<E>>;
    type Proof = WhirProof<MerkleTreeParams<E>, E>;
    // TODO: support both base and extension fields
    type Poly = CoefficientList<E::BasePrimeField>;
    type Transcript = Merlin<DefaultHash>;

    fn setup(poly_size: usize, num_polys: usize) -> Self::Param {
        let mv_params = MultivariateParameters::<E>::new(poly_size, num_polys);
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

    fn commit_and_write(
        pp: &Self::Param,
        poly: &Self::Poly,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let committer = Committer::new(pp.clone());
        let witness = committer.commit(transcript, poly.clone())?;
        Ok(witness.into())
    }

    // Assumption:
    // 1. there must be at least one polynomial
    // 2. all polynomials are in base field
    // (TODO: this assumption is from the whir implementation,
    // if we are going to support extension field, need modify whir's implementation)
    // 3. all polynomials must have the same number of variables
    fn batch_commit_and_write(
        pp: &Self::Param,
        polys: &[Self::Poly],
        transcript: &mut Self::Transcript,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        if polys.is_empty() {
            return Err(Error::InvalidPcsParam);
        }

        for i in 1..polys.len() {
            if polys[i].num_variables() != polys[0].num_variables() {
                return Err(Error::InvalidPcsParam);
            }
        }

        let committer = Committer::new(pp.clone());
        let witness = committer.batch_commit(transcript, polys)?;
        Ok(witness)
    }

    fn open(
        pp: &Self::Param,
        witness: Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        let prover = Prover(pp.clone());
        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let proof = prover.prove(transcript, statement, witness.into())?;
        Ok(proof)
    }

    fn simple_batch_open(
        pp: &Self::Param,
        witnesses: Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Proof, Error> {
        assert_eq!(witnesses.polys.len(), evals.len());
        let prover = Prover(pp.clone());
        let proof = prover.simple_batch_prove(transcript, point, evals, witnesses)?;
        Ok(proof)
    }

    fn verify(
        vp: &Self::Param,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &Self::Transcript,
    ) -> Result<(), Error> {
        // TODO: determine reps by security bits
        let reps = 1000;
        let verifier = Verifier::new(vp.clone());
        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&vp)
            .add_whir_proof(&vp);

        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        for _ in 0..reps {
            let mut arthur = io.to_arthur(transcript.transcript());
            verifier.verify(&mut arthur, &statement, proof)?;
        }
        Ok(())
    }

    fn simple_batch_verify(
        vp: &Self::Param,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &Self::Transcript,
    ) -> Result<(), Error> {
        let reps = 1000;
        let verifier = Verifier::new(vp.clone());
        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&vp)
            .add_whir_proof(&vp);

        for _ in 0..reps {
            let mut arthur = io.to_arthur(transcript.transcript());
            verifier.simple_batch_verify(&mut arthur, point, evals, proof)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use rand::Rng;

    use super::*;
    use crate::crypto::fields::Field64_2 as F;

    #[test]
    fn single_poly_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        let pp = Whir::<F>::setup(poly_size, 1);

        let poly = CoefficientList::new(
            (0..num_coeffs)
                .map(<F as Field>::BasePrimeField::from)
                .collect(),
        );

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);
        let mut merlin = io.to_merlin();

        let witness = Whir::<F>::commit_and_write(&pp, &poly, &mut merlin).unwrap();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&MultilinearPoint(point.clone()));

        let proof = Whir::<F>::open(&pp, witness, &point, &eval, &mut merlin).unwrap();
        Whir::<F>::verify(&pp, &point, &eval, &proof, &merlin).unwrap();
    }

    #[test]
    fn simple_batch_polys_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        let num_polys = 1 << 3;
        let pp = Whir::<F>::setup(poly_size, num_polys);

        let mut polys = Vec::new();
        for _ in 0..num_polys {
            let poly = CoefficientList::new(
                (0..num_coeffs)
                    .map(<F as Field>::BasePrimeField::from)
                    .collect(),
            );
            polys.push(poly);
        }

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);
        let mut merlin = io.to_merlin();

        let witness = Whir::<F>::batch_commit_and_write(&pp, &polys, &mut merlin).unwrap();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let evals = polys
            .iter()
            .map(|poly| poly.evaluate_at_extension(&MultilinearPoint(point.clone())))
            .collect::<Vec<_>>();

        let proof =
            Whir::<F>::simple_batch_open(&pp, witness, &point, &evals, &mut merlin).unwrap();
        Whir::<F>::simple_batch_verify(&pp, &point, &evals, &proof, &merlin).unwrap();
    }
}
