use super::{Statement, WhirProof, committer::Witness, parameters::WhirConfig};
use crate::{
    domain::Domain,
    ntt::expand_from_coeff,
    parameters::FoldType,
    poly_utils::{
        MultilinearPoint,
        coeffs::CoefficientList,
        fold::{compute_fold, restructure_evaluations},
    },
    sumcheck::prover_not_skipping::SumcheckProverNotSkipping,
    utils::{self, expand_randomness},
};
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, MultiPath};
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer};
use nimue::{
    ByteChallenges, ByteWriter, ProofResult,
    plugins::ark::{FieldChallenges, FieldWriter},
};
use nimue_pow::{self, PoWChallenge};

use crate::whir::fs_utils::{DigestWriter, get_challenge_stir_queries};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct Prover<F, MerkleConfig, PowStrategy>(pub WhirConfig<F, MerkleConfig, PowStrategy>)
where
    F: FftField,
    MerkleConfig: Config;

impl<F, MerkleConfig, PowStrategy> Prover<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
    PowStrategy: nimue_pow::PowStrategy,
{
    pub(crate) fn validate_parameters(&self) -> bool {
        self.0.mv_parameters.num_variables
            == self.0.folding_factor.total_number(self.0.n_rounds()) + self.0.final_sumcheck_rounds
    }

    fn validate_statement(&self, statement: &Statement<F>) -> bool {
        if statement.points.len() != statement.evaluations.len() {
            return false;
        }
        if !statement
            .points
            .iter()
            .all(|point| point.0.len() == self.0.mv_parameters.num_variables)
        {
            return false;
        }
        if !self.0.initial_statement && !statement.points.is_empty() {
            return false;
        }
        true
    }

    fn validate_witness(&self, witness: &Witness<F, MerkleConfig>) -> bool {
        assert_eq!(witness.ood_points.len(), witness.ood_answers.len());
        if !self.0.initial_statement {
            assert!(witness.ood_points.is_empty());
        }
        witness.polynomial.num_variables() == self.0.mv_parameters.num_variables
    }

    pub fn prove<Merlin>(
        &self,
        merlin: &mut Merlin,
        mut statement: Statement<F>,
        witness: Witness<F, MerkleConfig>,
    ) -> ProofResult<WhirProof<MerkleConfig, F>>
    where
        Merlin: FieldChallenges<F>
            + FieldWriter<F>
            + ByteChallenges
            + ByteWriter
            + PoWChallenge
            + DigestWriter<MerkleConfig>,
    {
        // If any evaluation point is shorter than the folding factor, pad with 0 in front
        for p in statement.points.iter_mut() {
            while p.n_variables() < self.0.folding_factor.at_round(0) {
                p.0.insert(0, F::ONE);
            }
        }

        assert!(self.validate_parameters());
        assert!(self.validate_statement(&statement));
        assert!(self.validate_witness(&witness));

        let timer = start_timer!(|| "Single Prover");
        let initial_claims: Vec<_> = witness
            .ood_points
            .into_iter()
            .map(|ood_point| {
                MultilinearPoint::expand_from_univariate(
                    ood_point,
                    self.0.mv_parameters.num_variables,
                )
            })
            .chain(statement.points)
            .collect();
        let initial_answers: Vec<_> = witness
            .ood_answers
            .into_iter()
            .chain(statement.evaluations)
            .collect();

        if !self.0.initial_statement {
            // It is ensured that if there is no initial statement, the
            // number of ood samples is also zero.
            assert!(
                initial_answers.is_empty(),
                "Can not have initial answers without initial statement"
            );
        }

        let mut sumcheck_prover = None;
        let folding_randomness = if self.0.initial_statement {
            // If there is initial statement, then we run the sum-check for
            // this initial statement.
            let [combination_randomness_gen] = merlin.challenge_scalars()?;
            let combination_randomness =
                expand_randomness(combination_randomness_gen, initial_claims.len());

            sumcheck_prover = Some(SumcheckProverNotSkipping::new(
                witness.polynomial.clone(),
                &initial_claims,
                &combination_randomness,
                &initial_answers,
            ));

            sumcheck_prover
                .as_mut()
                .unwrap()
                .compute_sumcheck_polynomials::<PowStrategy, Merlin>(
                    merlin,
                    self.0.folding_factor.at_round(0),
                    self.0.starting_folding_pow_bits,
                )?
        } else {
            // If there is no initial statement, there is no need to run the
            // initial rounds of the sum-check, and the verifier directly sends
            // the initial folding randomnesses.
            let mut folding_randomness = vec![F::ZERO; self.0.folding_factor.at_round(0)];
            merlin.fill_challenge_scalars(&mut folding_randomness)?;

            if self.0.starting_folding_pow_bits > 0. {
                merlin.challenge_pow::<PowStrategy>(self.0.starting_folding_pow_bits)?;
            }
            MultilinearPoint(folding_randomness)
        };

        let round_state = RoundState {
            domain: self.0.starting_domain.clone(),
            round: 0,
            sumcheck_prover,
            folding_randomness,
            coefficients: witness.polynomial,
            prev_merkle: witness.merkle_tree,
            prev_merkle_answers: witness.merkle_leaves,
            merkle_proofs: vec![],
        };

        let round_timer = start_timer!(|| "Single Round");
        let result = self.round(merlin, round_state);
        end_timer!(round_timer);

        end_timer!(timer);

        result
    }

    pub(crate) fn round<Merlin>(
        &self,
        merlin: &mut Merlin,
        mut round_state: RoundState<F, MerkleConfig>,
    ) -> ProofResult<WhirProof<MerkleConfig, F>>
    where
        Merlin: FieldChallenges<F>
            + ByteChallenges
            + FieldWriter<F>
            + ByteWriter
            + PoWChallenge
            + DigestWriter<MerkleConfig>,
    {
        // Fold the coefficients
        let folded_coefficients = round_state
            .coefficients
            .fold(&round_state.folding_randomness);

        let num_variables = self.0.mv_parameters.num_variables
            - self.0.folding_factor.total_number(round_state.round);
        // num_variables should match the folded_coefficients here.
        assert_eq!(num_variables, folded_coefficients.num_variables());

        // Base case
        if round_state.round == self.0.n_rounds() {
            // Directly send coefficients of the polynomial to the verifier.
            merlin.add_scalars(folded_coefficients.coeffs())?;

            // Final verifier queries and answers. The indices are over the
            // *folded* domain.
            let final_challenge_indexes = get_challenge_stir_queries(
                round_state.domain.size(), // The size of the *original* domain before folding
                self.0.folding_factor.at_round(round_state.round), /* The folding factor we used to fold the previous polynomial */
                self.0.final_queries,
                merlin,
            )?;

            let merkle_proof = round_state
                .prev_merkle
                .generate_multi_proof(final_challenge_indexes.clone())
                .unwrap();
            // Every query requires opening these many in the previous Merkle tree
            let fold_size = 1 << self.0.folding_factor.at_round(round_state.round);
            let answers = final_challenge_indexes
                .into_iter()
                .map(|i| {
                    round_state.prev_merkle_answers[i * fold_size..(i + 1) * fold_size].to_vec()
                })
                .collect();
            round_state.merkle_proofs.push((merkle_proof, answers));

            // PoW
            if self.0.final_pow_bits > 0. {
                merlin.challenge_pow::<PowStrategy>(self.0.final_pow_bits)?;
            }

            // Final sumcheck
            if self.0.final_sumcheck_rounds > 0 {
                round_state
                    .sumcheck_prover
                    .unwrap_or_else(|| {
                        SumcheckProverNotSkipping::new(folded_coefficients.clone(), &[], &[], &[])
                    })
                    .compute_sumcheck_polynomials::<PowStrategy, Merlin>(
                        merlin,
                        self.0.final_sumcheck_rounds,
                        self.0.final_folding_pow_bits,
                    )?;
            }

            return Ok(WhirProof(round_state.merkle_proofs));
        }

        let round_params = &self.0.round_parameters[round_state.round];

        // Fold the coefficients, and compute fft of polynomial (and commit)
        let new_domain = round_state.domain.scale(2);
        let expansion = new_domain.size() / folded_coefficients.num_coeffs();
        let evals = expand_from_coeff(folded_coefficients.coeffs(), expansion);
        // Group the evaluations into leaves by the *next* round folding factor
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals = utils::stack_evaluations(
            evals,
            self.0.folding_factor.at_round(round_state.round + 1), // Next round fold factor
        );
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            new_domain.backing_domain.group_gen(),
            new_domain.backing_domain.group_gen_inv(),
            self.0.folding_factor.at_round(round_state.round + 1),
        );

        #[cfg(not(feature = "parallel"))]
        let leafs_iter = folded_evals.chunks_exact(
            1 << self
                .0
                .folding_factor
                .get_folding_factor_of_round(round_state.round + 1),
        );
        #[cfg(feature = "parallel")]
        let leafs_iter = folded_evals
            .par_chunks_exact(1 << self.0.folding_factor.at_round(round_state.round + 1));
        let merkle_tree = MerkleTree::<MerkleConfig>::new(
            &self.0.leaf_hash_params,
            &self.0.two_to_one_params,
            leafs_iter,
        )
        .unwrap();

        let root = merkle_tree.root();
        merlin.add_digest(root)?;

        // OOD Samples
        let mut ood_points = vec![F::ZERO; round_params.ood_samples];
        let mut ood_answers = Vec::with_capacity(round_params.ood_samples);
        if round_params.ood_samples > 0 {
            merlin.fill_challenge_scalars(&mut ood_points)?;
            ood_answers.extend(ood_points.iter().map(|ood_point| {
                folded_coefficients.evaluate(&MultilinearPoint::expand_from_univariate(
                    *ood_point,
                    num_variables,
                ))
            }));
            merlin.add_scalars(&ood_answers)?;
        }

        // STIR queries
        let stir_challenges_indexes = get_challenge_stir_queries(
            round_state.domain.size(), // Current domain size *before* folding
            self.0.folding_factor.at_round(round_state.round), // Current fold factor
            round_params.num_queries,
            merlin,
        )?;
        // Compute the generator of the folded domain, in the extension field
        let domain_scaled_gen = round_state
            .domain
            .backing_domain
            .element(1 << self.0.folding_factor.at_round(round_state.round));
        let stir_challenges: Vec<_> = ood_points
            .into_iter()
            .chain(
                stir_challenges_indexes
                    .iter()
                    .map(|i| domain_scaled_gen.pow([*i as u64])),
            )
            .map(|univariate| MultilinearPoint::expand_from_univariate(univariate, num_variables))
            .collect();

        let merkle_proof = round_state
            .prev_merkle
            .generate_multi_proof(stir_challenges_indexes.clone())
            .unwrap();
        let fold_size = 1 << self.0.folding_factor.at_round(round_state.round);
        let answers: Vec<_> = stir_challenges_indexes
            .iter()
            .map(|i| round_state.prev_merkle_answers[i * fold_size..(i + 1) * fold_size].to_vec())
            .collect();
        // Evaluate answers in the folding randomness.
        let mut stir_evaluations = ood_answers.clone();
        match self.0.fold_optimisation {
            FoldType::Naive => {
                // See `Verifier::compute_folds_full`
                let domain_size = round_state.domain.backing_domain.size();
                let domain_gen = round_state.domain.backing_domain.element(1);
                let domain_gen_inv = domain_gen.inverse().unwrap();
                let coset_domain_size = 1 << self.0.folding_factor.at_round(round_state.round);
                // The domain (before folding) is split into cosets of size
                // `coset_domain_size` (which is just `fold_size`). Each coset
                // is generated by powers of `coset_generator` (which is just the
                // `fold_size`-root of unity) multiplied by a different
                // `coset_offset`.
                // For example, if `fold_size = 16`, and the domain size is N, then
                // the domain is (1, w, w^2, ..., w^(N-1)), the domain generator
                // is w, and the coset generator is w^(N/16).
                // The first coset is (1, w^(N/16), w^(2N/16), ..., w^(15N/16))
                // which is also a subgroup <w^(N/16)> itself (the coset_offset is 1).
                // The second coset would be w * <w^(N/16)>, the third coset would be
                // w^2 * <w^(N/16)>, and so on. Until w^(N/16-1) * <w^(N/16)>.
                let coset_generator_inv =
                    domain_gen_inv.pow([(domain_size / coset_domain_size) as u64]);
                stir_evaluations.extend(stir_challenges_indexes.iter().zip(&answers).map(
                    |(index, answers)| {
                        // The coset is w^index * <w_coset_generator>
                        // let _coset_offset = domain_gen.pow(&[*index as u64]);
                        let coset_offset_inv = domain_gen_inv.pow([*index as u64]);

                        // In the Naive mode, the oracle consists directly of the
                        // evaluations of f over the domain. We leverage an
                        // algorithm to compute the evaluations of the folded f
                        // at the corresponding point in folded domain (which is
                        // coset_offset^fold_size).
                        compute_fold(
                            answers,
                            &round_state.folding_randomness.0,
                            coset_offset_inv,
                            coset_generator_inv,
                            F::from(2).inverse().unwrap(),
                            self.0.folding_factor.at_round(round_state.round),
                        )
                    },
                ))
            }
            FoldType::ProverHelps => stir_evaluations.extend(answers.iter().map(|answers| {
                // In the ProverHelps mode, the oracle values have been linearly
                // transformed such that they are exactly the coefficients of the
                // multilinear polynomial whose evaluation at the folding randomness
                // is just the folding of f evaluated at the folded point.
                CoefficientList::new(answers.to_vec()).evaluate(&round_state.folding_randomness)
            })),
        }
        round_state.merkle_proofs.push((merkle_proof, answers));

        // PoW
        if round_params.pow_bits > 0. {
            merlin.challenge_pow::<PowStrategy>(round_params.pow_bits)?;
        }

        // Randomness for combination
        let [combination_randomness_gen] = merlin.challenge_scalars()?;
        let combination_randomness =
            expand_randomness(combination_randomness_gen, stir_challenges.len());

        let mut sumcheck_prover = round_state
            .sumcheck_prover
            .take()
            .map(|mut sumcheck_prover| {
                sumcheck_prover.add_new_equality(
                    &stir_challenges,
                    &combination_randomness,
                    &stir_evaluations,
                );
                sumcheck_prover
            })
            .unwrap_or_else(|| {
                SumcheckProverNotSkipping::new(
                    folded_coefficients.clone(),
                    &stir_challenges,
                    &combination_randomness,
                    &stir_evaluations,
                )
            });

        let folding_randomness = sumcheck_prover
            .compute_sumcheck_polynomials::<PowStrategy, Merlin>(
                merlin,
                self.0.folding_factor.at_round(round_state.round + 1),
                round_params.folding_pow_bits,
            )?;

        let round_state = RoundState {
            round: round_state.round + 1,
            domain: new_domain,
            sumcheck_prover: Some(sumcheck_prover),
            folding_randomness,
            coefficients: folded_coefficients, /* TODO: Is this redundant with `sumcheck_prover.coeff` ? */
            prev_merkle: merkle_tree,
            prev_merkle_answers: folded_evals,
            merkle_proofs: round_state.merkle_proofs,
        };

        self.round(merlin, round_state)
    }
}

pub(crate) struct RoundState<F, MerkleConfig>
where
    F: FftField,
    MerkleConfig: Config,
{
    pub(crate) round: usize,
    pub(crate) domain: Domain<F>,
    pub(crate) sumcheck_prover: Option<SumcheckProverNotSkipping<F>>,
    pub(crate) folding_randomness: MultilinearPoint<F>,
    pub(crate) coefficients: CoefficientList<F>,
    pub(crate) prev_merkle: MerkleTree<MerkleConfig>,
    pub(crate) prev_merkle_answers: Vec<F>,
    pub(crate) merkle_proofs: Vec<(MultiPath<MerkleConfig>, Vec<Vec<F>>)>,
}
