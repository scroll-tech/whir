# Using Packing for Batched WHIR Proofs

In this document, we discuss a new strategy to produced batched WHIR proofs called packing.

## Implementation
We implemented our packing strategy in `batch_effectiveness_packing.py`. The next step is to integrate the packing result into our main WHIR batching effectiveness test.

## Packing Overview
Let $p_1, \dots p_n$ be $n$ multilinear polynomials of various size. We want to batch open each $p_i$ on a different point $x_i$. Denote $v_i$ to be the number of variables of variables for each $p_i$, we assume that _the polynomials are order by their size in decreasing order_, i.e. $\forall i, v_i \geq v_{i+1}$

We want to pack $p_1, \dots p_n$ into new polynomials $p_1^*, \dots p_m^*$ with variables $v_1^*, \dots v_m^*$ the goal is to have as many $v_j^* = v_1$ as possible, while minimizing the size of the paddings $\sum_j |0_j^*|$. To demonstrate the packing process, let $p_j^*$ be the packed polynomial of $p_i\dots p_{i+k}$, then
* $v_j^* \geq \sum_{d=i}^{i+k} v_d$
* Let $e_j^*$ be the coefficients of $p_j^*$, represented using $2^{v_j^*}$ terms, and $e_d$ be the coefficients of each poly $p_d$, then
$$e_j^* = e_i || e_{i+1} || \dots || e_{i+k} || 0_j^*$$
where $||$ denotes vector concatenation, and $0_j^*$ is a length-$2^{v_j^* - \sum v_d}$ 0-vector.

## Finding The Optimal Way to Pack
Given a packing threshold $t$, compute pad size limit $0_{\max} = \frac{t}{100}\cdot (\sum |e_i|)$. The goal is to minimize the number of unique $v_j^*$, while ensuring $\sum |0_j^*| \leq 0_{\max}$.

### A Simple Packing Algorithm

We first present our simpliest packing algorithm: each packed polynomial $p_j^*$ is expressed as its number of variables $v_j^*$ together with a binary tree $t_j^*$: starting from the root (depth 0), each leaf of depth $k$ points to either a component polynomial with $v_j^* - k$ variables, or empty. 

Pack all polynomials in order (i.e. decreasing number of variables). To pack polynomial $p_i$ into $p_j^*$, we consider 3 cases:
1. If $p_j^*$ has empty space, then we use _Corollary 1_ below to show that $|0_j^*| \geq |e_i|$. Find the next empty leaf in $t_j^*$ in pre-order. If the depth of the empty leaf matches with $v_i$, assign $p_i$ to the leaf; otherwise, keep branching off the leaf and its left children until the correct depth, assign $p_i$ to the left-most leaf.
2. If $p_j^*$ is full and $v_j^* < v_1$, increment $v_j^*$ by 1 and add a new root to $t_j^*$, so that the depth of $t_j^*$ is incremented by 1, the left subtree of $t_j^*$ is the original tree, and the right subtree is an empty leaf. Perform case 1 afterwards.
3. If $p_j^*$ is full and $v_j^* = v_1$, then we need a new packed poly. Initialize $p_{j+1}^*$ such that $v_{j+1}^* = v_i$ and the root of $t_{j+1}^*$ is $p_i$. This is also the case for $p_1$, which initializes $p_1^*$.

### Observations and Theorems
Since all $v_i$ are in decreasing order, we can deduce the following theorems and lemmas from our tree construction.

***Theorem 1***: At every stage of packing, the pad size $|0_j^*|$ is divisible by the size of the smallest packed poly $|e_{i-1}| = 2^{v_{i-1}}$.
> Proof: $|0_j^*| = |e_j^*| - \sum_d |e_d| = 2^{v_j^*} - \sum_d 2^{v_d}$ for some $d \leq i-1$. Since $v_j^*\geq v_{i-1}$ and $v_d\geq v_{i-1}$, both $|e_j^*|$ and all of $|e_d|$ are divisible by $|e_{i-1}|$, so $|0_j^*|$ is divisible by $|e_{i-1}|$.

***Corollary 1***: When packing polynomial $p_i$ into $p_j^*$, either $|0_j^*| = 0$, or $|0_j^*| \geq |e_i|$.
> Proof: Since all polynomials are packed in order, $p_{i-1}$ must be packed into $p_j^*$. Since $v_i$ are in decreasing order, $|e_{i-1}|$ must be the size of the smallest packed poly, and $|e_{i-1}|$ must be divisible by $|e_i|$. Thus, $|0_j^*|$ must be divisible by $|e_i|$, so either $|0_j^*| = 0$, or $|0_j^*| \geq |e_i|$.

***Corollary 2***: No padding is ever needed between components $e_i$ of a packed poly $e_j^*$. Since every $e_i$ already begins at an index divisible by $|e_i|$.

***Theorem 2***: At the end of the protocol, $\sum_j |0_j^*| = |0_m^*|$: i.e. every pad occurs on the final packed poly.
> Proof: This is the direct result of the protocol, which does not initialize a new packed poly until the previous one is full. The protocol itself is enabled by Corollary 1, which states that if a packed poly is not full, it can always fit the next poly.

***Corollary 3***: Fix every $v_j^*$, no other strategy can achieve fewer $\sum_j |0_j^*|$ than the simple algorithm. Since every pad in the simple algorithm occurs when it reaches the end of the poly list.

***Corollary 4***: The left subtree of $t_m^*$ is full, so $p_m^*$ can be split into $(p_l^*, p_r^*)$, where $v_l^* = v_m^* - 1$ and $v_r^* = v_m^* - q$, reducing pad size by $2^{q-1}$.
> Note: This is the most efficient way to reduce pad size. However, this might not produce the minimum number of unique $v_i^*$. To do so, one might have to further split $p_l^*$. It is unclear whether there are scenarios where that would be helpful.

### The Optimal Packing Strategy
From corollary 3 and 4, we conclude that the optimal strategy for packing is as follows:
1. Use the simple algorithm to produce $p_0^*\dots p_m^*$
2. Repeatedly splitting $p_m^*$ until $\sum_j |0_j^*| \leq 0_{\max}$ 

We further note that if no pad is allowed, then eventually all polys of $p_m^*$ will form packed poly of their own, ensuring $\sum_j |0_j^*| = 0$. So step 2 will terminate.

## Applying Packing to WHIR

## Cost-Analysis of Packing
Let $d_i = p_i + 1$. The starting domain of the RS code for each polynomial $p_i$ is $2^{d_i}$. Let $f$ be the folding factor, the WHIR proof protocol for each polynomial (standalone) $p_i$ proceeds as follows:
* At the beginning, $\mathcal{P}$ commits to a merkle tree $m_i^{(1)}$ on the RS code of $p_i$, with leaf size $8f$ bytes, intermediate node size 32 bytes, and depth $v_i - f$.
* During each round $j$, $\mathcal{P}$ and $\mathcal{V}$:
  * Performs a $f$-round sumcheck to produce $p_i^{(j)}$ with $v_i^{(j)} = v_i^{(j-1)} - f$ variables
  * Samples and verifies $q_i^{(j)}$ queries on $m_i^{(j)}$
  * Computes $d_i^{(j)} = d_i^{(j-1)} - 1$, and $\mathcal{P}$ commits to a merkle tree $m_i^{(j+1)}$ on the RS code of $p_i^{(j)}$, with leaf size $16f$ bytes, intermediate node size 32 bytes, and depth $v_i^{(j)} - f$.
* Repeat until $v_i^{(d)} < f$ for some round $d$. Perform a final $v_i$-round sumcheck.

