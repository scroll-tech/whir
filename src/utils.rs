use crate::ntt::transpose;
use crate::whir::fs_utils::DigestWriter;

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use ark_ff::Field;
use nimue::{
    plugins::ark::{FieldChallenges, FieldWriter},
    ByteChallenges, ByteWriter, ProofResult,
};
use nimue_pow::PoWChallenge;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::collections::BTreeSet;

// checks whether the given number n is a power of two.
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1) == 0)
}

/// performs big-endian binary decomposition of `value` and returns the result.
///
/// `n_bits` must be at must usize::BITS. If it is strictly smaller, the most significant bits of `value` are ignored.
/// The returned vector v ends with the least significant bit of `value` and always has exactly `n_bits` many elements.
pub fn to_binary(value: usize, n_bits: usize) -> Vec<bool> {
    // Ensure that n is within the bounds of the input integer type
    assert!(n_bits <= usize::BITS as usize);
    let mut result = vec![false; n_bits];
    for i in 0..n_bits {
        result[n_bits - 1 - i] = (value & (1 << i)) != 0;
    }
    result
}

// TODO(Gotti): n_bits is a misnomer if base > 2. Should be n_limbs or sth.
// Also, should the behaviour for value >= base^n_bits be specified as part of the API or asserted not to happen?
// Currently, we compute the decomposition of value % (base^n_bits).

/// decomposes value into its big-endian base-ary decomposition, meaning we return a vector v, s.t.
///
/// value = v[0]*base^(n_bits-1) + v[1] * base^(n_bits-2) + ... + v[n_bits-1] * 1,
/// where each v[i] is in 0..base.
/// The returned vector always has length exactly n_bits (we pad with leading zeros);
pub fn base_decomposition(value: usize, base: u8, n_bits: usize) -> Vec<u8> {
    // Initialize the result vector with zeros of the specified length
    let mut result = vec![0u8; n_bits];

    // Create a mutable copy of the value for computation
    // Note: We could just make the local passed-by-value argument `value` mutable, but this is clearer.
    let mut value = value;

    // Compute the base decomposition
    for i in 0..n_bits {
        result[n_bits - 1 - i] = (value % (base as usize)) as u8;
        value /= base as usize;
    }
    // TODO: Should we assert!(value == 0) here to check that the orginally passed `value` is < base^n_bits ?

    result
}

// Gotti: Consider renaming this function. The name sounds like it's a PRG.
// TODO (Gotti): Check that ordering is actually correct at point of use (everything else is big-endian).

/// expand_randomness outputs the vector [1, base, base^2, base^3, ...] of length len.
pub fn expand_randomness<F: Field>(base: F, len: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(len);
    let mut acc = F::ONE;
    for _ in 0..len {
        res.push(acc);
        acc *= base;
    }

    res
}

/// Deduplicates AND orders a vector
pub fn dedup<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    Vec::from_iter(BTreeSet::from_iter(v))
}

// FIXME(Gotti): comment does not match what function does (due to mismatch between folding_factor and folding_factor_exp)
// Also, k should be defined: k = evals.len() / 2^{folding_factor}, I guess.

/// Takes the vector of evaluations (assume that evals[i] = f(omega^i))
/// and folds them into a vector of such that folded_evals[i] = [f(omega^(i + k * j)) for j in 0..folding_factor]
pub fn stack_evaluations<F: Field>(mut evals: Vec<F>, folding_factor: usize) -> Vec<F> {
    let folding_factor_exp = 1 << folding_factor;
    assert!(evals.len() % folding_factor_exp == 0);
    let size_of_new_domain = evals.len() / folding_factor_exp;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose(&mut evals, folding_factor_exp, size_of_new_domain);
    evals
}

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
pub fn horizontal_stacking<F: Field>(
    evals: Vec<F>,
    domain_size: usize,
    folding_factor: usize,
) -> Vec<F> {
    let fold_size = 1 << folding_factor;
    let num_polys: usize = evals.len() / domain_size;
    let num_polys_log2: usize = num_polys.ilog2() as usize;

    let mut evals = stack_evaluations(evals, num_polys_log2);
    #[cfg(not(feature = "parallel"))]
    let stacked_evals = evals.chunks_exact_mut(fold_size * num_polys);
    #[cfg(feature = "parallel")]
    let stacked_evals = evals.par_chunks_exact_mut(fold_size * num_polys);
    stacked_evals.for_each(|eval| stack_evaluations_mut(eval, folding_factor));
    evals
}

// generate a random vector for batching open/verify
pub fn generate_random_vector<F, Merlin, MerkleConfig>(
    merlin: &mut Merlin,
    size: usize,
) -> ProofResult<Vec<F>>
where
    F: Field,
    MerkleConfig: Config,
    Merlin: FieldChallenges<F>
        + FieldWriter<F>
        + ByteChallenges
        + ByteWriter
        + PoWChallenge
        + DigestWriter<MerkleConfig>,
{
    let [gamma] = merlin.challenge_scalars()?;
    let res = expand_randomness(gamma, size);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::utils::base_decomposition;

    use super::{horizontal_stacking, is_power_of_two, stack_evaluations, to_binary};

    #[test]
    fn test_horizontal_stacking() {
        use crate::crypto::fields::Field64 as F;

        let num = 256;
        let domain_size = 128;
        let folding_factor = 3;
        let fold_size = 1 << folding_factor;
        assert_eq!(num % fold_size, 0);
        let evals: Vec<_> = (0..num as u64).map(F::from).collect();

        let stacked = horizontal_stacking(evals, domain_size, folding_factor);
        assert_eq!(stacked.len(), num);

        for (i, fold) in stacked.chunks_exact(fold_size).enumerate() {
            assert_eq!(fold.len(), fold_size);
            let offset = if i % 2 == 0 { 0 } else { domain_size };
            let row_id = i / 2;
            for j in 0..fold_size {
                assert_eq!(fold[j], F::from((offset + row_id * fold_size + j) as u64));
            }
        }
    }

    #[test]
    fn test_evaluations_stack() {
        use crate::crypto::fields::Field64 as F;

        let num = 256;
        let folding_factor = 3;
        let fold_size = 1 << folding_factor;
        assert_eq!(num % fold_size, 0);
        let evals: Vec<_> = (0..num as u64).map(F::from).collect();

        let stacked = stack_evaluations(evals, folding_factor);
        assert_eq!(stacked.len(), num);

        for (i, fold) in stacked.chunks_exact(fold_size).enumerate() {
            assert_eq!(fold.len(), fold_size);
            for j in 0..fold_size {
                assert_eq!(fold[j], F::from((i + j * num / fold_size) as u64));
            }
        }
    }

    #[test]
    fn test_to_binary() {
        assert_eq!(to_binary(0b10111, 5), vec![true, false, true, true, true]);
        assert_eq!(to_binary(0b11001, 2), vec![false, true]); // truncate
        let empty_vec: Vec<bool> = vec![]; // just for the explicit bool type.
        assert_eq!(to_binary(1, 0), empty_vec);
        assert_eq!(to_binary(0, 0), empty_vec);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0));
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(usize::MAX));
    }

    #[test]
    fn test_base_decomposition() {
        assert_eq!(base_decomposition(0b1011, 2, 6), vec![0, 0, 1, 0, 1, 1]);
        assert_eq!(base_decomposition(15, 3, 3), vec![1, 2, 0]);
        // check truncation: This checks the current (undocumented) behaviour (compute modulo base^number_of_limbs) works as believed.
        // If we actually specify the API to have a different behaviour, this test should change.
        assert_eq!(base_decomposition(15 + 81, 3, 3), vec![1, 2, 0]);
    }
}
