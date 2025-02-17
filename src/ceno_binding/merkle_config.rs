use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use nimue::{Arthur, DefaultHash, IOPattern, Merlin, ProofResult};
use nimue_pow::PowStrategy;

use crate::crypto::merkle_tree::blake3::MerkleTreeParams as Blake3Params;
use crate::crypto::merkle_tree::keccak::MerkleTreeParams as KeccakParams;
use crate::poly_utils::coeffs::CoefficientList;
use crate::whir::committer::{Committer, Witness};
use crate::whir::fs_utils::DigestWriter;
use crate::whir::iopattern::WhirIOPattern;
use crate::whir::parameters::WhirConfig;
use crate::whir::prover::Prover;
use crate::whir::verifier::Verifier;
use crate::whir::{Statement, WhirProof};

pub trait WhirMerkleConfigWrapper<F: FftField> {
    type MerkleConfig: Config<Leaf = [F]> + Clone;
    type PowStrategy: PowStrategy;

    fn commit_to_merlin(
        committer: &Committer<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin<DefaultHash>,
        poly: CoefficientList<F::BasePrimeField>,
    ) -> ProofResult<Witness<F, Self::MerkleConfig>>;

    fn prove_with_merlin(
        prover: &Prover<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin,
        statement: Statement<F>,
        witness: Witness<F, Self::MerkleConfig>,
    ) -> ProofResult<WhirProof<Self::MerkleConfig, F>>;

    fn verify_with_arthur(
        verifier: &Verifier<F, Self::MerkleConfig, Self::PowStrategy>,
        arthur: &mut Arthur,
        statement: &Statement<F>,
        whir_proof: &WhirProof<Self::MerkleConfig, F>,
    ) -> ProofResult<<Self::MerkleConfig as Config>::InnerDigest>;

    fn commit_statement_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern;

    fn add_whir_proof_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern;

    fn add_digest_to_merlin(
        merlin: &mut Merlin,
        digest: <Self::MerkleConfig as Config>::InnerDigest,
    ) -> ProofResult<()>;
}

pub struct Blake3ConfigWrapper<F: FftField>(Blake3Params<F>);
pub struct KeccakConfigWrapper<F: FftField>(KeccakParams<F>);

impl<F: FftField> WhirMerkleConfigWrapper<F> for Blake3ConfigWrapper<F> {
    type MerkleConfig = Blake3Params<F>;
    type PowStrategy = nimue_pow::blake3::Blake3PoW;
    fn commit_to_merlin(
        committer: &Committer<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin<DefaultHash>,
        poly: CoefficientList<F::BasePrimeField>,
    ) -> ProofResult<Witness<F, Self::MerkleConfig>> {
        committer.commit(merlin, poly)
    }

    fn prove_with_merlin(
        prover: &Prover<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin,
        statement: Statement<F>,
        witness: Witness<F, Self::MerkleConfig>,
    ) -> ProofResult<WhirProof<Self::MerkleConfig, F>> {
        prover.prove(merlin, statement, witness)
    }

    fn verify_with_arthur(
        verifier: &Verifier<F, Self::MerkleConfig, Self::PowStrategy>,
        arthur: &mut Arthur,
        statement: &Statement<F>,
        whir_proof: &WhirProof<Self::MerkleConfig, F>,
    ) -> ProofResult<<Self::MerkleConfig as Config>::InnerDigest> {
        verifier.verify(arthur, statement, whir_proof)
    }

    fn commit_statement_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern {
        iopattern.commit_statement(params)
    }

    fn add_whir_proof_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern {
        iopattern.add_whir_proof(params)
    }

    fn add_digest_to_merlin(
        merlin: &mut Merlin,
        digest: <Self::MerkleConfig as Config>::InnerDigest,
    ) -> ProofResult<()> {
        <Merlin as DigestWriter<Self::MerkleConfig>>::add_digest(merlin, digest)
    }
}

impl<F: FftField> WhirMerkleConfigWrapper<F> for KeccakConfigWrapper<F> {
    type MerkleConfig = KeccakParams<F>;
    type PowStrategy = nimue_pow::keccak::KeccakPoW;
    fn commit_to_merlin(
        committer: &Committer<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin<DefaultHash>,
        poly: CoefficientList<F::BasePrimeField>,
    ) -> ProofResult<Witness<F, Self::MerkleConfig>> {
        committer.commit(merlin, poly)
    }

    fn prove_with_merlin(
        prover: &Prover<F, Self::MerkleConfig, Self::PowStrategy>,
        merlin: &mut Merlin,
        statement: Statement<F>,
        witness: Witness<F, Self::MerkleConfig>,
    ) -> ProofResult<WhirProof<Self::MerkleConfig, F>> {
        prover.prove(merlin, statement, witness)
    }

    fn verify_with_arthur(
        verifier: &Verifier<F, Self::MerkleConfig, Self::PowStrategy>,
        arthur: &mut Arthur,
        statement: &Statement<F>,
        whir_proof: &WhirProof<Self::MerkleConfig, F>,
    ) -> ProofResult<<Self::MerkleConfig as Config>::InnerDigest> {
        verifier.verify(arthur, statement, whir_proof)
    }

    fn commit_statement_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern {
        iopattern.commit_statement(params)
    }

    fn add_whir_proof_to_io_pattern(
        iopattern: IOPattern,
        params: &WhirConfig<F, Self::MerkleConfig, Self::PowStrategy>,
    ) -> IOPattern {
        iopattern.add_whir_proof(params)
    }

    fn add_digest_to_merlin(
        merlin: &mut Merlin,
        digest: <Self::MerkleConfig as Config>::InnerDigest,
    ) -> ProofResult<()> {
        <Merlin as DigestWriter<Self::MerkleConfig>>::add_digest(merlin, digest)
    }
}
