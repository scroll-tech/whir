use crate::{
    ntt::expand_from_coeff,
    poly_utils::{coeffs::CoefficientList, fold::restructure_evaluations, MultilinearPoint},
    utils,
    whir::committer::{Committer, Witness},
};
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use derive_more::Debug;
use nimue::{
    plugins::ark::{FieldChallenges, FieldWriter},
    ByteWriter, ProofResult,
};

use crate::whir::fs_utils::DigestWriter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct Witnesses<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    pub(crate) polys: Vec<CoefficientList<F>>,
    #[debug(skip)]
    pub(crate) merkle_tree: MerkleTree<MerkleConfig>,
    pub(crate) merkle_leaves: Vec<F>,
    pub(crate) ood_points: Vec<F>,
    pub(crate) ood_answers: Vec<F>,
}

impl<F, MerkleConfig: Config> From<Witness<F, MerkleConfig>> for Witnesses<F, MerkleConfig> {
    fn from(witness: Witness<F, MerkleConfig>) -> Self {
        Self {
            polys: vec![witness.polynomial],
            merkle_tree: witness.merkle_tree,
            merkle_leaves: witness.merkle_leaves,
            ood_points: witness.ood_points,
            ood_answers: witness.ood_answers,
        }
    }
}

impl<F: Clone, MerkleConfig: Config> From<Witnesses<F, MerkleConfig>> for Witness<F, MerkleConfig> {
    fn from(witness: Witnesses<F, MerkleConfig>) -> Self {
        Self {
            polynomial: witness.polys[0].clone(),
            merkle_tree: witness.merkle_tree,
            merkle_leaves: witness.merkle_leaves,
            ood_points: witness.ood_points,
            ood_answers: witness.ood_answers,
        }
    }
}

impl<F, MerkleConfig, PowStrategy> Committer<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
{
    pub fn batch_commit<Merlin>(
        &self,
        merlin: &mut Merlin,
        polys: &[CoefficientList<F::BasePrimeField>],
    ) -> ProofResult<Witnesses<F, MerkleConfig>>
    where
        Merlin: FieldWriter<F> + FieldChallenges<F> + ByteWriter + DigestWriter<MerkleConfig>,
    {
        let base_domain = self.0.starting_domain.base_domain.unwrap();
        let expansion = base_domain.size() / polys[0].num_coeffs();
        let evals = polys
            .iter()
            .map(|poly| expand_from_coeff(poly.coeffs(), expansion))
            .collect::<Vec<Vec<_>>>();

        assert_eq!(base_domain.size(), evals[0].len());

        let folded_evals = evals
            .into_iter()
            .map(|evals| utils::stack_evaluations(evals, self.0.folding_factor))
            .map(|evals| {
                restructure_evaluations(
                    evals,
                    self.0.fold_optimisation,
                    base_domain.group_gen(),
                    base_domain.group_gen_inv(),
                    self.0.folding_factor,
                )
            })
            .flat_map(|evals| {
                evals
                    .into_iter()
                    .map(F::from_base_prime_field)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let folded_evals = super::utils::horizontal_stacking(
            folded_evals,
            base_domain.size(),
            self.0.folding_factor,
        );

        // Group folds together as a leaf.
        let fold_size = 1 << self.0.folding_factor;
        #[cfg(not(feature = "parallel"))]
        let leafs_iter = folded_evals.chunks_exact(fold_size * polys.len());
        #[cfg(feature = "parallel")]
        let leafs_iter = folded_evals.par_chunks_exact(fold_size * polys.len());

        let merkle_tree = MerkleTree::<MerkleConfig>::new(
            &self.0.leaf_hash_params,
            &self.0.two_to_one_params,
            leafs_iter,
        )
        .unwrap();

        let root = merkle_tree.root();

        merlin.add_digest(root)?;

        let mut ood_points = vec![F::ZERO; self.0.committment_ood_samples];
        let mut ood_answers = vec![F::ZERO; polys.len() * self.0.committment_ood_samples];
        if self.0.committment_ood_samples > 0 {
            merlin.fill_challenge_scalars(&mut ood_points)?;
            ood_points
                .iter()
                .enumerate()
                .for_each(|(point_index, ood_point)| {
                    for j in 0..polys.len() {
                        let eval = polys[j].evaluate_at_extension(
                            &MultilinearPoint::expand_from_univariate(
                                *ood_point,
                                self.0.mv_parameters.num_variables,
                            ),
                        );
                        ood_answers[point_index * polys.len() + j] = eval;
                    }
                });
            merlin.add_scalars(&ood_answers)?;
        }

        let polys = polys
            .into_iter()
            .map(|poly| poly.clone().to_extension())
            .collect::<Vec<_>>();

        Ok(Witnesses {
            polys,
            merkle_tree,
            merkle_leaves: folded_evals,
            ood_points,
            ood_answers,
        })
    }
}
