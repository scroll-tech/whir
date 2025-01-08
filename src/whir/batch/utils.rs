use crate::ntt::transpose;
use ark_ff::Field;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Takes the vector of evaluations (assume that evals[i] = f(omega^i))
/// and folds them into a vector of such that folded_evals[i] = [f(omega^(i + k * j)) for j in 0..folding_factor]
/// This function will mutate the function without return
pub fn stack_evaluations_mut<F: Field>(evals: &mut [F], folding_factor: usize) {
    let folding_factor_exp = 1 << folding_factor;
    assert!(evals.len() % folding_factor_exp == 0);
    let size_of_new_domain = evals.len() / folding_factor_exp;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose(evals, folding_factor_exp, size_of_new_domain);
}

/// Takes a vector of matrix and stacking them horizontally
/// Use in-place matrix transposes to avoid data copy
/// each matrix has domain_size elements
/// each matrix has shape (*, 1<<folding_factor)
pub fn horizontal_stacking<F: Field>(
    evals: Vec<F>,
    domain_size: usize,
    folding_factor: usize,
) -> Vec<F> {
    let fold_size = 1 << folding_factor;
    let num_polys: usize = evals.len() / domain_size;
    let num_polys_log2: usize = num_polys.ilog2() as usize;

    let mut evals = crate::utils::stack_evaluations(evals, num_polys_log2);
    #[cfg(not(feature = "parallel"))]
    let stacked_evals = evals.chunks_exact_mut(fold_size * num_polys);
    #[cfg(feature = "parallel")]
    let stacked_evals = evals.par_chunks_exact_mut(fold_size * num_polys);
    stacked_evals.for_each(|eval| stack_evaluations_mut(eval, folding_factor));
    evals
}
