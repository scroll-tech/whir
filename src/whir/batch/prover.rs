use super::committer::Witnesses;
use crate::sumcheck::prover_not_skipping_batched::SumcheckProverNotSkippingBatched;
use crate::whir::prover::RoundState;
use crate::whir::{prover::Prover, WhirProof};
use crate::{
    ntt::expand_from_coeff,
    parameters::FoldType,
    poly_utils::{
        coeffs::CoefficientList,
        fold::{compute_fold, restructure_evaluations},
        MultilinearPoint,
    },
    sumcheck::prover_not_skipping::SumcheckProverNotSkipping,
    utils::{self, expand_randomness},
};
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer};
use itertools::zip_eq;
use nimue::{
    plugins::ark::{FieldChallenges, FieldWriter},
    ByteChallenges, ByteWriter, ProofResult,
};
use nimue_pow::{self, PoWChallenge};

use crate::whir::fs_utils::{get_challenge_stir_queries, DigestWriter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

struct RoundStateBatch<'a, F, MerkleConfig>
where
    F: FftField,
    MerkleConfig: Config,
{
    round_state: RoundState<F, MerkleConfig>,
    batching_randomness: Vec<F>,
    prev_merkle: &'a MerkleTree<MerkleConfig>,
    prev_merkle_answers: &'a Vec<F>,
}

impl<F, MerkleConfig, PowStrategy> Prover<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
    PowStrategy: nimue_pow::PowStrategy,
{
    fn validate_witnesses(&self, witness: &Witnesses<F, MerkleConfig>) -> bool {
        assert_eq!(
            witness.ood_points.len() * witness.polys.len(),
            witness.ood_answers.len()
        );
        if !self.0.initial_statement {
            assert!(witness.ood_points.is_empty());
        }
        assert!(!witness.polys.is_empty(), "Input polys cannot be empty");
        witness.polys.iter().skip(1).for_each(|poly| {
            assert_eq!(
                poly.num_variables(),
                witness.polys[0].num_variables(),
                "All polys must have the same number of variables"
            );
        });
        witness.polys[0].num_variables() == self.0.mv_parameters.num_variables
    }

    /// batch open the same points for multiple polys
    pub fn simple_batch_prove<Merlin>(
        &self,
        merlin: &mut Merlin,
        points: &Vec<MultilinearPoint<F>>,
        evals_per_point: &Vec<Vec<F>>, // outer loop on each point, inner loop on each poly
        witness: &Witnesses<F, MerkleConfig>,
    ) -> ProofResult<WhirProof<MerkleConfig, F>>
    where
        Merlin: FieldChallenges<F>
            + FieldWriter<F>
            + ByteChallenges
            + ByteWriter
            + PoWChallenge
            + DigestWriter<MerkleConfig>,
    {
        let prove_timer = start_timer!(|| "prove");
        let initial_timer = start_timer!(|| "init");
        assert!(self.0.initial_statement, "must be true for pcs");
        assert!(self.validate_parameters());
        assert!(self.validate_witnesses(&witness));
        for point in points {
            assert_eq!(
                point.0.len(),
                self.0.mv_parameters.num_variables,
                "number of variables mismatch"
            );
        }
        let num_polys = witness.polys.len();
        for evals in evals_per_point {
            assert_eq!(
                evals.len(),
                num_polys,
                "number of polynomials not equal number of evaluations"
            );
        }

        let compute_dot_product =
            |evals: &[F], coeff: &[F]| -> F { zip_eq(evals, coeff).map(|(a, b)| *a * *b).sum() };
        end_timer!(initial_timer);

        let random_coeff_timer = start_timer!(|| "random coeff");
        let random_coeff =
            super::utils::generate_random_vector_batch_open(merlin, witness.polys.len())?;
        end_timer!(random_coeff_timer);

        let initial_claims_timer = start_timer!(|| "initial claims");
        let initial_claims: Vec<_> = witness
            .ood_points
            .par_iter()
            .map(|ood_point| {
                MultilinearPoint::expand_from_univariate(
                    *ood_point,
                    self.0.mv_parameters.num_variables,
                )
            })
            .chain(points.clone()).collect();
        end_timer!(initial_claims_timer);

        let ood_answers_timer = start_timer!(|| "ood answers");
        let ood_answers = witness
            .ood_answers
            .par_chunks_exact(witness.polys.len())
            .map(|answer| compute_dot_product(answer, &random_coeff))
            .collect::<Vec<_>>();
        end_timer!(ood_answers_timer);

        let eval_timer = start_timer!(|| "eval");
        let eval_per_point: Vec<F> = evals_per_point.par_iter().map(|evals| compute_dot_product(evals, &random_coeff)).collect();
        end_timer!(eval_timer);

        let combine_timer = start_timer!(|| "Combine polynomial");
        let initial_answers: Vec<_> = ood_answers
            .into_iter()
            .chain(eval_per_point)
            .collect();

        let polynomial = CoefficientList::combine(&witness.polys, &random_coeff);
        end_timer!(combine_timer);

        let comb_timer = start_timer!(|| "combination randomness");
        let [combination_randomness_gen] = merlin.challenge_scalars()?;
        let combination_randomness =
            expand_randomness(combination_randomness_gen, initial_claims.len());
        end_timer!(comb_timer);

        let sumcheck_timer = start_timer!(|| "sumcheck");
        let mut sumcheck_prover = Some(SumcheckProverNotSkipping::new(
            polynomial.clone(),
            &initial_claims,
            &combination_randomness,
            &initial_answers,
        ));
        end_timer!(sumcheck_timer);

        let sumcheck_prover_timer = start_timer!(|| "sumcheck_prover");
        let folding_randomness = sumcheck_prover
            .as_mut()
            .unwrap()
            .compute_sumcheck_polynomials::<PowStrategy, Merlin>(
                merlin,
                self.0.folding_factor,
                self.0.starting_folding_pow_bits,
            )?;
        end_timer!(sumcheck_prover_timer);

        let timer = start_timer!(|| "round_batch");
        let round_state = RoundStateBatch {
            round_state: RoundState {
                domain: self.0.starting_domain.clone(),
                round: 0,
                sumcheck_prover,
                folding_randomness,
                coefficients: polynomial,
                prev_merkle: MerkleTree::blank(
                    &self.0.leaf_hash_params,
                    &self.0.two_to_one_params,
                    2,
                )
                .unwrap(),
                prev_merkle_answers: Vec::new(),
                merkle_proofs: vec![],
            },
            prev_merkle: &witness.merkle_tree,
            prev_merkle_answers: &witness.merkle_leaves,
            batching_randomness: random_coeff,
        };

        let result = self.simple_round_batch(merlin, round_state, num_polys);
        end_timer!(timer);
        end_timer!(prove_timer);

        result
    }

    fn simple_round_batch<Merlin>(
        &self,
        merlin: &mut Merlin,
        round_state: RoundStateBatch<F, MerkleConfig>,
        num_polys: usize,
    ) -> ProofResult<WhirProof<MerkleConfig, F>>
    where
        Merlin: FieldChallenges<F>
            + ByteChallenges
            + FieldWriter<F>
            + ByteWriter
            + PoWChallenge
            + DigestWriter<MerkleConfig>,
    {
        let batching_randomness = round_state.batching_randomness;
        let prev_merkle = round_state.prev_merkle;
        let prev_merkle_answers = round_state.prev_merkle_answers;
        let mut round_state = round_state.round_state;
        // Fold the coefficients
        let folded_coefficients = round_state
            .coefficients
            .fold(&round_state.folding_randomness);

        let num_variables =
            self.0.mv_parameters.num_variables - (round_state.round + 1) * self.0.folding_factor;

        // Base case
        if round_state.round == self.0.n_rounds() {
            // Coefficients of the polynomial
            merlin.add_scalars(folded_coefficients.coeffs())?;

            // Final verifier queries and answers
            let final_challenge_indexes = get_challenge_stir_queries(
                round_state.domain.size(),
                self.0.folding_factor,
                self.0.final_queries,
                merlin,
            )?;

            let merkle_proof = prev_merkle
                .generate_multi_proof(final_challenge_indexes.clone())
                .unwrap();
            let fold_size = 1 << self.0.folding_factor;
            let answers = final_challenge_indexes
                .into_par_iter()
                .map(|i| prev_merkle_answers[i * (fold_size * num_polys)..(i + 1) * (fold_size * num_polys)].to_vec())
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
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals = utils::stack_evaluations(evals, self.0.folding_factor);
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            new_domain.backing_domain.group_gen(),
            new_domain.backing_domain.group_gen_inv(),
            self.0.folding_factor,
        );

        #[cfg(not(feature = "parallel"))]
        let leafs_iter = folded_evals.chunks_exact(1 << self.0.folding_factor);
        #[cfg(feature = "parallel")]
        let leafs_iter = folded_evals.par_chunks_exact(1 << self.0.folding_factor);
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
            round_state.domain.size(),
            self.0.folding_factor,
            round_params.num_queries,
            merlin,
        )?;
        let domain_scaled_gen = round_state
            .domain
            .backing_domain
            .element(1 << self.0.folding_factor);
        let stir_challenges: Vec<_> = ood_points
            .into_par_iter()
            .chain(
                stir_challenges_indexes
                    .par_iter()
                    .map(|i| domain_scaled_gen.pow([*i as u64])),
            )
            .map(|univariate| MultilinearPoint::expand_from_univariate(univariate, num_variables))
            .collect();

        let merkle_proof = prev_merkle
            .generate_multi_proof(stir_challenges_indexes.clone())
            .unwrap();
        let fold_size = (1 << self.0.folding_factor) * num_polys;
        let answers = stir_challenges_indexes
            .par_iter()
            .map(|i| prev_merkle_answers[i * fold_size..(i + 1) * fold_size].to_vec())
            .collect::<Vec<_>>();
        let batched_answers = answers
            .par_iter()
            .map(|answer| {
                let chunk_size = 1 << self.0.folding_factor;
                let mut res = vec![F::ZERO; chunk_size];
                for i in 0..chunk_size {
                    for j in 0..num_polys {
                        res[i] += answer[i + j * chunk_size] * batching_randomness[j];
                    }
                }
                res
            })
            .collect::<Vec<_>>();
        // Evaluate answers in the folding randomness.
        let mut stir_evaluations = ood_answers.clone();
        match self.0.fold_optimisation {
            FoldType::Naive => {
                // See `Verifier::compute_folds_full`
                let domain_size = round_state.domain.backing_domain.size();
                let domain_gen = round_state.domain.backing_domain.element(1);
                let domain_gen_inv = domain_gen.inverse().unwrap();
                let coset_domain_size = 1 << self.0.folding_factor;
                let coset_generator_inv =
                    domain_gen_inv.pow([(domain_size / coset_domain_size) as u64]);
                stir_evaluations.extend(stir_challenges_indexes.iter().zip(&batched_answers).map(
                    |(index, batched_answers)| {
                        // The coset is w^index * <w_coset_generator>
                        //let _coset_offset = domain_gen.pow(&[*index as u64]);
                        let coset_offset_inv = domain_gen_inv.pow([*index as u64]);

                        compute_fold(
                            batched_answers,
                            &round_state.folding_randomness.0,
                            coset_offset_inv,
                            coset_generator_inv,
                            F::from(2).inverse().unwrap(),
                            self.0.folding_factor,
                        )
                    },
                ))
            }
            FoldType::ProverHelps => {
                stir_evaluations.extend(batched_answers.iter().map(|batched_answers| {
                    CoefficientList::new(batched_answers.to_vec())
                        .evaluate(&round_state.folding_randomness)
                }))
            }
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
                self.0.folding_factor,
                round_params.folding_pow_bits,
            )?;

        let round_state = RoundState {
            round: round_state.round + 1,
            domain: new_domain,
            sumcheck_prover: Some(sumcheck_prover),
            folding_randomness,
            coefficients: folded_coefficients, // TODO: Is this redundant with `sumcheck_prover.coeff` ?
            prev_merkle: merkle_tree,
            prev_merkle_answers: folded_evals,
            merkle_proofs: round_state.merkle_proofs,
        };

        self.round(merlin, round_state)
    }
}

impl<F, MerkleConfig, PowStrategy> Prover<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
    PowStrategy: nimue_pow::PowStrategy,
{
    /// each poly on a different point, same size
    pub fn same_size_batch_prove<Merlin>(
        &self,
        merlin: &mut Merlin,
        point_per_poly: &Vec<MultilinearPoint<F>>,
        eval_per_poly: &Vec<F>,
        witness: &Witnesses<F, MerkleConfig>,
    ) -> ProofResult<WhirProof<MerkleConfig, F>>
    where
        Merlin: FieldChallenges<F>
            + FieldWriter<F>
            + ByteChallenges
            + ByteWriter
            + PoWChallenge
            + DigestWriter<MerkleConfig>,
    {
        let prove_timer = start_timer!(|| "prove");
        let initial_timer = start_timer!(|| "init");
        assert!(self.0.initial_statement, "must be true for pcs");
        assert!(self.validate_parameters());
        assert!(self.validate_witnesses(&witness));
        for point in point_per_poly {
            assert_eq!(
                point.0.len(),
                self.0.mv_parameters.num_variables,
                "number of variables mismatch"
            );
        }
        let num_polys = witness.polys.len();
        assert_eq!(
            eval_per_poly.len(),
            num_polys,
            "number of polynomials not equal number of evaluations"
        );
        end_timer!(initial_timer);

        let poly_comb_randomness_timer = start_timer!(|| "poly comb randomness");
        let poly_comb_randomness =
            super::utils::generate_random_vector_batch_open(merlin, witness.polys.len())?;
        end_timer!(poly_comb_randomness_timer);

        let initial_claims_timer = start_timer!(|| "initial claims");
        let initial_eval_claims = point_per_poly.clone();
        end_timer!(initial_claims_timer);

        let sumcheck_timer = start_timer!(|| "unifying sumcheck");
        let mut sumcheck_prover = SumcheckProverNotSkippingBatched::new(
            witness.polys.clone(),
            &initial_eval_claims,
            &poly_comb_randomness,
            &eval_per_poly,
        );

        // Perform the entire sumcheck
        let folded_point = sumcheck_prover
            .compute_sumcheck_polynomials::<PowStrategy, Merlin>(
                merlin,
                self.0.mv_parameters.num_variables,
                0.,
            )?;
        let folded_evals = sumcheck_prover.get_folded_polys();
        merlin.add_scalars(&folded_evals)?;
        // Problem now reduced to the polys(folded_point) =?= folded_evals
        end_timer!(sumcheck_timer);

        let timer = start_timer!(|| "simple_batch");
        // perform simple_batch on folded_point and folded_evals
        let result = self.simple_batch_prove(merlin, &vec![folded_point], &vec![folded_evals], witness)?;
        end_timer!(timer);
        end_timer!(prove_timer);

        Ok(result)
    }
}