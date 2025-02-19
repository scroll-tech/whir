use super::proof::SumcheckPolynomial;
use crate::{poly_utils::{coeffs::CoefficientList, evals::EvaluationsList, MultilinearPoint}, sumcheck::prover_single::SumcheckSingle};
use ark_ff::Field;
#[cfg(feature = "parallel")]
use rayon::{join, prelude::*};

pub struct SumcheckBatched<F> {
    // The evaluation on each p and eq
    evaluations_of_p: Vec<EvaluationsList<F>>,
    evaluations_of_equality: Vec<EvaluationsList<F>>,
    comb_coeff: Vec<F>,
    num_polys: usize,
    num_variables: usize,
    sum: F,
}

impl<F> SumcheckBatched<F>
where
    F: Field,
{
    // Input includes the following:
    // coeffs: coefficient of a list of polynomials p
    // seq_points: points that will be evaluated on every polynomial (OOD points)
    // par_points: one point per poly (eval points)
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = comb_coeff0 * p0(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...) + comb_coeff1 * p1(..) * eq1(..) + ...
    pub fn new(
        coeffs: Vec<CoefficientList<F>>,
        seq_points: &[MultilinearPoint<F>],
        par_points: &[MultilinearPoint<F>],
        point_comb_coeff: &[F], // random coefficients for combining each point
        poly_comb_coeff: &[F], // random coefficients for combining each poly
        seq_evals_per_point: &[Vec<F>],
        par_evals: &[F],
    ) -> Self {
        let num_polys = coeffs.len();
        assert_eq!(point_comb_coeff.len(), seq_points.len() + 1); // 1 for par_points
        assert_eq!(poly_comb_coeff.len(), num_polys);
        assert_eq!(par_points.len(), num_polys);
        for seq_evals in seq_evals_per_point {
            assert_eq!(seq_evals.len(), num_polys);
        }
        assert_eq!(par_evals.len(), num_polys);
        let num_variables = coeffs[0].num_variables();

        let mut prover = SumcheckBatched {
            evaluations_of_p: coeffs.into_iter().map(|c| c.into()).collect(),
            evaluations_of_equality: vec![EvaluationsList::new(vec![F::ZERO; 1 << num_variables]); num_polys],
            comb_coeff: poly_comb_coeff.to_vec(),
            num_polys,
            num_variables,
            sum: F::ZERO,
        };

        prover.add_new_equality(seq_points, par_points, point_comb_coeff, poly_comb_coeff, seq_evals_per_point, par_evals);
        prover
    }

    #[cfg(not(feature = "parallel"))]
    pub fn compute_sumcheck_polynomial(&self) -> SumcheckPolynomial<F> {
        panic!("Non-parallel version not supported!");
        assert!(self.num_variables >= 1);

        // Compute coefficients of the quadratic result polynomial
        let eval_p_iter = self.evaluation_of_p.evals().chunks_exact(2);
        let eval_eq_iter = self.evaluation_of_equality.evals().chunks_exact(2);
        let (c0, c2) = eval_p_iter
            .zip(eval_eq_iter)
            .map(|(p_at, eq_at)| {
                // Convert evaluations to coefficients for the linear fns p and eq.
                let (p_0, p_1) = (p_at[0], p_at[1] - p_at[0]);
                let (eq_0, eq_1) = (eq_at[0], eq_at[1] - eq_at[0]);

                // Now we need to add the contribution of p(x) * eq(x)
                (p_0 * eq_0, p_1 * eq_1)
            })
            .reduce(|(a0, a2), (b0, b2)| (a0 + b0, a2 + b2))
            .unwrap_or((F::ZERO, F::ZERO));

        // Use the fact that self.sum = p(0) + p(1) = 2 * c0 + c1 + c2
        let c1 = self.sum - c0.double() - c2;

        // Evaluate the quadratic polynomial at 0, 1, 2
        let eval_0 = c0;
        let eval_1 = c0 + c1 + c2;
        let eval_2 = eval_1 + c1 + c2 + c2.double();

        SumcheckPolynomial::new(vec![eval_0, eval_1, eval_2], 1)
    }

    #[cfg(feature = "parallel")]
    pub fn compute_sumcheck_polynomial(&self) -> SumcheckPolynomial<F> {
        assert!(self.num_variables >= 1);
        
        // Compute coefficients of the quadratic result polynomial
        let (_, c0, c2) = self.comb_coeff.par_iter().zip(&self.evaluations_of_p).zip(&self.evaluations_of_equality).map(|((rand, eval_p), eval_eq)| {
            let eval_p_iter = eval_p.evals().par_chunks_exact(2);
            let eval_eq_iter = eval_eq.evals().par_chunks_exact(2);
            let (c0, c2) = eval_p_iter
                .zip(eval_eq_iter)
                .map(|(p_at, eq_at)| {
                    // Convert evaluations to coefficients for the linear fns p and eq.
                    let (p_0, p_1) = (p_at[0], p_at[1] - p_at[0]);
                    let (eq_0, eq_1) = (eq_at[0], eq_at[1] - eq_at[0]);

                    // Now we need to add the contribution of p(x) * eq(x)
                    (p_0 * eq_0, p_1 * eq_1)
                })
                .reduce(
                    || (F::ZERO, F::ZERO),
                    |(a0, a2), (b0, b2)| (a0 + b0, a2 + b2),
                );
            (rand.clone(), c0, c2)
        }).reduce(
            || (F::ONE, F::ZERO, F::ZERO),
            |(r0, a0, a2), (r1, b0, b2)| (F::ONE, r0 * a0 + r1 * b0, r0 * a2 + r1 * b2),
        );

        // Use the fact that self.sum = p(0) + p(1) = 2 * coeff_0 + coeff_1 + coeff_2
        let c1 = self.sum - c0.double() - c2;

        // Evaluate the quadratic polynomial at 0, 1, 2
        let eval_0 = c0;
        let eval_1 = c0 + c1 + c2;
        let eval_2 = eval_1 + c1 + c2 + c2.double();

        SumcheckPolynomial::new(vec![eval_0, eval_1, eval_2], 1)
    }

    pub fn add_new_equality(
        &mut self,
        seq_points: &[MultilinearPoint<F>],
        par_points: &[MultilinearPoint<F>],
        point_comb_coeff: &[F],
        poly_comb_coeff: &[F],
        seq_evals_per_point: &[Vec<F>],
        par_evals: &[F],
    ) {
        assert_eq!(seq_points.len(), seq_evals_per_point.len());
        assert_eq!(par_points.len(), par_evals.len());
        // OOD points
        // TODO: optimize the processes below: EQs of every SEQ_POINTS should only be computed once!
        for (i, (point, seq_point_coeff)) in seq_points.iter().zip(point_comb_coeff).enumerate() {
            for evals in &mut self.evaluations_of_equality {
                SumcheckSingle::eval_eq(&point.0, evals.evals_mut(), *seq_point_coeff);
            }
            for j in 0..self.num_polys {
                self.sum += poly_comb_coeff[j] * seq_evals_per_point[i][j] * seq_point_coeff;
            }
        }
        
        // Eval points
        let par_point_coeff = point_comb_coeff[seq_points.len()];
        for (i, point) in par_points.iter().enumerate() {
            SumcheckSingle::eval_eq(&point.0, self.evaluations_of_equality[i].evals_mut(), par_point_coeff);
            self.sum += poly_comb_coeff[i] * par_evals[i] * par_point_coeff;
        }
    }

    // When the folding randomness arrives, compress the table accordingly (adding the new points)
    #[cfg(not(feature = "parallel"))]
    pub fn compress(
        &mut self,
        combination_randomness: F, // Scale the initial point
        folding_randomness: &MultilinearPoint<F>,
        sumcheck_poly: &SumcheckPolynomial<F>,
    ) {
        panic!("Non-parallel version not supported!");
        assert_eq!(folding_randomness.n_variables(), 1);
        assert!(self.num_variables >= 1);

        let randomness = folding_randomness.0[0];
        let evaluations_of_p = self
            .evaluation_of_p
            .evals()
            .chunks_exact(2)
            .map(|at| (at[1] - at[0]) * randomness + at[0])
            .collect();
        let evaluations_of_eq = self
            .evaluation_of_equality
            .evals()
            .chunks_exact(2)
            .map(|at| (at[1] - at[0]) * randomness + at[0])
            .collect();

        // Update
        self.num_variables -= 1;
        self.evaluation_of_p = EvaluationsList::new(evaluations_of_p);
        self.evaluation_of_equality = EvaluationsList::new(evaluations_of_eq);
        self.sum = combination_randomness * sumcheck_poly.evaluate_at_point(folding_randomness);
    }

    #[cfg(feature = "parallel")]
    pub fn compress(
        &mut self,
        combination_randomness: F, // Scale the initial point
        folding_randomness: &MultilinearPoint<F>,
        sumcheck_poly: &SumcheckPolynomial<F>,
    ) {
        assert_eq!(folding_randomness.n_variables(), 1);
        assert!(self.num_variables >= 1);

        let randomness = folding_randomness.0[0];
        let evaluations: Vec<_> = self.evaluations_of_p.par_iter().zip(&self.evaluations_of_equality).map(|(eval_p, eval_eq)| {
            let (evaluation_of_p, evaluation_of_eq) = join(
                || {
                    eval_p
                        .evals()
                        .par_chunks_exact(2)
                        .map(|at| (at[1] - at[0]) * randomness + at[0])
                        .collect()
                },
                || {
                    eval_eq
                        .evals()
                        .par_chunks_exact(2)
                        .map(|at| (at[1] - at[0]) * randomness + at[0])
                        .collect()
                },
            );
            (EvaluationsList::new(evaluation_of_p), EvaluationsList::new(evaluation_of_eq))
        }).collect();
        let (evaluations_of_p, evaluations_of_eq)= evaluations.into_iter().unzip();

        // Update
        self.num_variables -= 1;
        self.evaluations_of_p = evaluations_of_p;
        self.evaluations_of_equality = evaluations_of_eq;
        self.sum = combination_randomness * sumcheck_poly.evaluate_at_point(folding_randomness);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::fields::Field64,
        poly_utils::{coeffs::CoefficientList, MultilinearPoint},
    };

    use super::SumcheckBatched;

    type F = Field64;

    #[test]
    fn test_sumcheck_folding_factor_1() {
        let num_rounds = 2;
        let ood_points = vec![
            MultilinearPoint(vec![F::from(4574), F::from(6839)]),
            MultilinearPoint(vec![F::from(9283), F::from(4792)]),
        ];
        let eval_points = vec![
            MultilinearPoint(vec![F::from(10), F::from(11)]),
            MultilinearPoint(vec![F::from(7), F::from(8)]),
        ];
        let polynomials = vec![
            CoefficientList::new(vec![F::from(1), F::from(5), F::from(10), F::from(14)]),
            CoefficientList::new(vec![F::from(2), F::from(6), F::from(11), F::from(13)]),
        ];
        let point_comb_coeffs = vec![F::from(4), F::from(5), F::from(6)];
        let poly_comb_coeffs = vec![F::from(2), F::from(3)];

        let seq_evals: Vec<Vec<F>> = ood_points.iter().map(|point|
            polynomials.iter().map(|poly|
                poly.evaluate(point)
            ).collect()
        ).collect();
        let par_evals: Vec<F> = polynomials.iter().zip(&eval_points).map(|(poly, point)| 
            poly.evaluate(point)
        ).collect();
        let mut claimed_value: F = seq_evals
            .iter()
            .zip(&point_comb_coeffs)
            .fold(F::from(0), |sum, (evals, point_rand)|
                evals
                .iter()
                .zip(&poly_comb_coeffs)
                .fold(F::from(0), |sum, (eval, poly_rand)| 
                    eval * poly_rand + sum
                ) * point_rand + sum
            ) 
        + par_evals
            .iter()
            .zip(&poly_comb_coeffs)
            .fold(F::from(0), |sum, (eval, poly_rand)| 
                eval * poly_rand + sum
            ) * point_comb_coeffs[ood_points.len()];
        
        let mut prover = SumcheckBatched::new(
            polynomials.clone(), 
            &ood_points,
            &eval_points, 
            &point_comb_coeffs,
            &poly_comb_coeffs,
            &seq_evals,
            &par_evals,
        );
        let mut comb_randomness_list = Vec::new();
        let mut fold_randomness_list = Vec::new();

        for _ in 0..num_rounds {
            let poly = prover.compute_sumcheck_polynomial();

            // First, check that is sums to the right value over the hypercube
            assert_eq!(poly.sum_over_hypercube(), claimed_value);

            let next_comb_randomness = F::from(100101);
            let next_fold_randomness = MultilinearPoint(vec![F::from(4999)]);

            prover.compress(next_comb_randomness, &next_fold_randomness, &poly);
            claimed_value = next_comb_randomness * poly.evaluate_at_point(&next_fold_randomness);

            comb_randomness_list.push(next_comb_randomness);
            fold_randomness_list.extend(next_fold_randomness.0);
        }
        println!("CLAIM:");
        for poly in prover.evaluations_of_p {
            println!("POLY: {:?}", poly);
        }
        println!("EXPECTED:");
        let fold_randomness_list = MultilinearPoint(fold_randomness_list);
        for poly in polynomials {
            println!("EVAL: {:?}", poly.evaluate(&fold_randomness_list));
        }
    }
}