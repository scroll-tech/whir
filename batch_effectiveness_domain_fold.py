# TODO: we are still left with the final design choice: what if poly[0] have enough var for ff but nout enough for ff+ff_diff?

from math import log, ceil
from collections import Counter
# Soundness types
CONJECTURE_LIST = 0
PROVABLE_LIST = 1
UNIQUE_DECODING = 2

# --
# INPUTS
poly_num_vars = [27, 26, 25, 24, 23, 22]
folding_factor = 4
soundness_type = CONJECTURE_LIST
pow_bits = 0
# --

def print_bytes(num_bytes):
  suffix = "bytes"
  if num_bytes > 1000:
    num_bytes /= 1000
    suffix = "KB"
  if num_bytes > 1000:
    num_bytes /= 1000
    suffix = "MB"
  if num_bytes > 1000:
    num_bytes /= 1000
    suffix = "GB"
  if num_bytes > 1000:
    num_bytes /= 1000
    suffix = "TB"
  return f"{num_bytes:.3f} {suffix}"

class MerkleData:
  def __init__(self, domain_exponent, num_polys, folding_factor, is_starting_poly):
    assert(is_starting_poly or num_polys == 1)  # sanity check
    self.domain_size = 2 ** domain_exponent
    self.num_polys = num_polys  # number of polynomials packed into this merkle tree
    self.folding_factor = folding_factor
    self.is_starting_poly = is_starting_poly  # if is_starting_poly, leafs cost 8 bytes instead of 16

class SumcheckData:
  def __init__(self, num_vars_list, num_rounds):
    self.num_vars_list = num_vars_list  # num of vars of all the polynomials involved in the sumcheck
    self.num_rounds = num_rounds

class QueryData:
  def __init__(self, num_queries, merkle_data):
    self.num_queries = num_queries
    self.merkle_data = merkle_data

class RawCost:
  # domain_size_list includes the domain size of EVERY TREE (same poly different round)
  # query_data_list includes EVERY QUERY
  def __init__(self, merkle_data_list, unify_sumcheck_data_list, fold_sumcheck_data_list, query_data_list):
    self.merkle_data_list = merkle_data_list
    self.unify_sumcheck_data_list = unify_sumcheck_data_list
    self.fold_sumcheck_data_list = fold_sumcheck_data_list
    self.query_data_list = query_data_list

  def get_prover_verifier_cost(self):
    # Overview
    print("MERKLE NUM LEAFS: ", [m.domain_size for m in self.merkle_data_list])
    print("UNIFY SUMCHECK NUM ROUNDS: ", [d.num_rounds for d in self.unify_sumcheck_data_list])
    r = Counter([s.num_rounds for s in self.fold_sumcheck_data_list])
    print(f"FOLD SUMCHECK NUM ROUNDS: {" + ".join([f"{i[1]} x {i[0]} rounds each" for i in r.items()])}")
    print("NUM QUERIES: ", [q.num_queries for q in self.query_data_list])

    # Merkle
    print("--")
    total_merkle_cost = 0
    for m in self.merkle_data_list:
      num_leafs = m.domain_size // m.folding_factor
      # Leaf size
      if m.is_starting_poly:
        total_merkle_cost += 8 * num_leafs * m.folding_factor * m.num_polys
      else:
        total_merkle_cost += 16 * num_leafs * m.folding_factor
      # Intermediate node size
      total_merkle_cost += 32 * (num_leafs - 1)
    print(f"TOTAL MERKLE TREE SIZE: {print_bytes(total_merkle_cost)}")

    # Sumcheck
    print("--")
    total_sumcheck_size = 0
    total_sumcheck_round = 0
    for s in self.unify_sumcheck_data_list + self.fold_sumcheck_data_list:
      total_sumcheck_round += s.num_rounds
      poly_size_list = [2 ** num_vars for num_vars in s.num_vars_list]
      for _ in range(0, s.num_rounds):
        total_sumcheck_size += sum(poly_size_list)
        poly_size_list = [poly_size // 2 if poly_size > 1 else 1 for poly_size in poly_size_list]
    print("TOTAL SUMCHECK EVAL SIZE: ", total_sumcheck_size)
    print("TOTAL SUMCHECK ROUND: ", total_sumcheck_round)

    # Queries
    print("--")
    total_num_queries = 0
    total_query_depth = 0
    total_query_size = 0
    for q in self.query_data_list:
      total_num_queries += q.num_queries
      m = q.merkle_data
      folded_domain_exponent = ceil(log(m.domain_size // m.folding_factor))
      total_query_depth += q.num_queries * (folded_domain_exponent + 1)
      if m.is_starting_poly:
        total_query_size += 8 * q.num_queries * m.folding_factor * m.num_polys
      else:
        total_query_size += 16 * q.num_queries * m.folding_factor
      total_query_size += 32 * q.num_queries * folded_domain_exponent
    print("TOTAL NUM QUERIES: ", total_num_queries)
    print("TOTAL QUERY DEPTH: ", total_query_depth)
    print("TOTAL QUERY SIZE: ", print_bytes(total_query_size))

# Compute number of queries
def get_num_queries(soundness_type, pow_bits, domain_exponent, num_vars):
  security_level = max(0, 100 - pow_bits)
  log_inv_rate = domain_exponent - num_vars
  if soundness_type == UNIQUE_DECODING:
    rate = 1 / (1 << log_inv_rate)
    denom = log((0.5 * (1. + rate)), 2)
    return ceil(-1 * security_level / denom)
  elif soundness_type == PROVABLE_LIST:
    return ceil(2 * security_level / log_inv_rate)
  elif soundness_type == CONJECTURE_LIST:
    return ceil(security_level / log_inv_rate)

# Assumes poly_domain_exponent is sorted in decreasing order
# Returns:
# 0: the size of every unique domain
# 1: the number of polys associated with it
# 2: the starting folding factor of each domain
def get_unique_domain_exponent(poly_domain_exponent, poly_num_vars, folding_factor, max_domain_exponent_fold):
  assert(len(poly_domain_exponent) == len(poly_num_vars))
  unique_domains = []
  num_polys_per_domain = []
  poly_size_per_domain = []  # num_vars of the largest poly of each domain
  for i in range(len(poly_domain_exponent)):
    d = poly_domain_exponent[i]
    p = poly_num_vars[i]
    if len(unique_domains) == 0 or unique_domains[-1] != d:
      unique_domains.append(d)
      num_polys_per_domain.append(1)
      poly_size_per_domain.append(p)
    else:
      num_polys_per_domain[-1] += 1
      poly_size_per_domain[-1] = max(poly_size_per_domain[-1], p)
  
  if max_domain_exponent_fold == 1:
    return (unique_domains, num_polys_per_domain, [folding_factor] * len(unique_domains))
  
  # Compute the folding factor of each starting domain (polynomials of all domains will be unified)
  # This involves the following process: let there be n domains, d_0, ..., d_n-1, sorted by (strictly) decreasing order
  #                                      let ff be the folding factor
  # 1. Starting by processing the first k domains that differ by at most n-1, denote the smallest domain of them d_min,
  #    fold each domain d_k by ff + d_k - d_min rounds
  # 2. Determine whether WHIR would finish these domains before reaching d_k (if exist). If so, remove d_0...d_k-1, 
  #    otherwise replace d_0..d_k-1 with a single d_0' = d_k + 1
  # 3. Repeat step 1 and 2 on the new list until all domains are removed.
  folding_factor_per_domain = []
  folded_domains = unique_domains[:]
  folded_poly_size = poly_size_per_domain[:]
  while len(folded_domains) > 0:
    next_folding_factors = get_folding_factors(folded_domains, folding_factor, max_domain_exponent_fold)
    folding_factor_per_domain.extend(next_folding_factors)
    k = len(next_folding_factors)
    if k == len(folded_domains):
      break
    num_folds = folded_poly_size[k - 1] // folding_factor
    if folded_domains[k - 1] - num_folds >= folded_domains[k]:
      # (k-1)th poly is going to be folded before d_k
      folded_domains = folded_domains[k:]
      folded_poly_size = folded_poly_size[k:]
    else:
      # add d_k + 1 term to represent the folded polys
      folded_poly_size = [folded_poly_size[k - 1] - folding_factor * (folded_domains[k - 1] - folded_domains[k] - 1)] + folded_poly_size[k:]
      folded_domains = [folded_domains[k] + 1] + folded_domains[k:]
  return (unique_domains, num_polys_per_domain, folding_factor_per_domain)

# Assume domains are strictly decreasing, returns:
# - folding factor for the k domain
# - len(folding factor) that denotes k
def get_folding_factors(domains, folding_factor, max_domain_exponent_fold):
  # Obtain the first k domains within max_domain_exponent_fold
  max_domain = domains[0]
  k = 1
  while k < len(domains) and max_domain - domains[k] < max_domain_exponent_fold:
    k += 1
  min_domain = domains[k - 1]
  return [folding_factor + domain - min_domain for domain in domains[:k]]

# Compute the cost if no batching occurs
def compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor):
  merkle_data_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  for num_var in poly_num_vars:
    domain_exponent = num_var + 1
    prev_merkle_data = MerkleData(domain_exponent, 1, folding_factor, True)
    merkle_data_list.append(prev_merkle_data)
    while num_var >= folding_factor:
      fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
      query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_exponent, num_var), prev_merkle_data))
      num_var -= folding_factor
      if num_var >= folding_factor:
        domain_exponent -= 1
        prev_merkle_data = MerkleData(domain_exponent, 1, folding_factor, False)
        merkle_data_list.append(prev_merkle_data)
    # Final sumcheck
    if num_var > 1:
      fold_sumcheck_data_list.append(SumcheckData([num_var], num_var))
  return RawCost(merkle_data_list, [], fold_sumcheck_data_list, query_data_list)

def compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor):
  # Do not pad, compute domain size for each poly
  poly_domain_exponent = [num_var + 1 for num_var in poly_num_vars]
  num_unique_domain_size = len(set(poly_domain_exponent))
  return (poly_domain_exponent, num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_exponent, 1))

def compute_batch_all_pad(soundness_type, pow_bits, poly_num_vars, folding_factor):
  # Pad every polynomial to the largest domain
  poly_domain_exponent = [poly_num_vars[0] + 1] * len(poly_num_vars)
  num_unique_domain_size = 1
  return (poly_domain_exponent, num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_exponent, 1))

def compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, threshold, max_domain_exponent_fold):
  # The prover is allowed extra (threshold)% of starting domain size
  poly_domain_exponent = [num_var + 1 for num_var in poly_num_vars]
  total_domain_size = lambda poly_domain_exponent : sum([2 ** domain_exponent for domain_exponent in poly_domain_exponent])
  target_domain_size = int(total_domain_size(poly_domain_exponent) * (1 + threshold / 100))
  # Repeatedly increase the domain size (exponent) of the smallest polys
  next_entry_to_pad = len(poly_domain_exponent) - 1
  while next_entry_to_pad > 0 and poly_domain_exponent[next_entry_to_pad - 1] == poly_domain_exponent[next_entry_to_pad]:
    next_entry_to_pad -= 1
  prev_poly_domain_exponent = poly_domain_exponent[:]
  while next_entry_to_pad > 0 and total_domain_size(poly_domain_exponent) < target_domain_size:
    prev_poly_domain_exponent = poly_domain_exponent[:]
    # Pad domain of every poly >= next_entry_to_pad to poly_domain_exponent[next_entry_to_pad - 1]
    for i in range(next_entry_to_pad, len(poly_domain_exponent)):
      poly_domain_exponent[i] = poly_domain_exponent[next_entry_to_pad - 1]
    # Find new next_entry_to_pad
    while next_entry_to_pad > 0 and poly_domain_exponent[next_entry_to_pad - 1] == poly_domain_exponent[next_entry_to_pad]:
      next_entry_to_pad -= 1
  # Revert to the domain size and next pad before threshold
  poly_domain_exponent = prev_poly_domain_exponent
  num_unique_domain_size = len(set(poly_domain_exponent))
  return (poly_domain_exponent, num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_exponent, max_domain_exponent_fold))

# max_domain_exponent_fold determines the maximum factor the domain size can change in one folding round
# 1 - domain size is only allowed to change by 2
# n - if the domain size of the n largest polys (p1...pn) differ by at most n - 1, 
#     perform (folding_factor + n - i)-folding on pi with domain size / 2^i
def compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_exponent, max_domain_exponent_fold):
  # Per-domain information
  (unique_domains, num_polys_per_domain, folding_factor_per_domain) = get_unique_domain_exponent(poly_domain_exponent, poly_num_vars, folding_factor, max_domain_exponent_fold)
  # For queries
  merkle_data_per_domain = [MerkleData(unique_domains[i], num_polys_per_domain[i], folding_factor_per_domain[i], True) for i in range(len(unique_domains))]
  merkle_data_list = merkle_data_per_domain[:]
  unify_sumcheck_data_list = []
  fold_sumcheck_data_list = []
  query_data_list = []

  # Assume poly_num_vars is sorted
  # Remove entries from poly_num_vars and poly_domain_exponent as polys are unified
  poly_num_vars = poly_num_vars[:]
  poly_domain_exponent = poly_domain_exponent[:]

  # Check if this is the first round of a WHIR proof
  # If it is not, then if any new polys are added, need to query on the merkle tree of both the folded poly and new poly
  # If a polynomial is completely folded and there are still (smaller) polynomials remaining, the next round is "first round" as well
  first_round = True
  while len(poly_num_vars) > 0:
    # If num_vars < folding_factor, this polynomial reaches the final round
    if len(poly_num_vars) > 0 and poly_num_vars[0] < folding_factor:
      # Final sumcheck
      if poly_num_vars[0] > 1:
        fold_sumcheck_data_list.append(SumcheckData([poly_num_vars[0]], poly_num_vars[0]))
      poly_num_vars = poly_num_vars[1:]
      poly_domain_exponent = poly_domain_exponent[1:]
      first_round = True
    if len(poly_num_vars) == 0:
      break
    
    # perform unification on polynomials of the k largest domains
    max_domain_exponent = poly_domain_exponent[0]
    unify_num_polys = 0
    unify_sumcheck_num_vars_list = []
    # if not first_round, query the folded poly and new poly separatedly even if they share the same domain
    folded_poly_query = not first_round and len(poly_domain_exponent) > 1 and poly_domain_exponent[0] == poly_domain_exponent[1]
    while unify_num_polys < len(poly_domain_exponent) and max_domain_exponent - poly_domain_exponent[unify_num_polys] < max_domain_exponent_fold:
      unify_sumcheck_num_vars_list.append(poly_num_vars[unify_num_polys])
      while unify_num_polys + 1 < len(poly_domain_exponent) and poly_domain_exponent[unify_num_polys] == poly_domain_exponent[unify_num_polys + 1]:
        unify_sumcheck_num_vars_list.append(poly_num_vars[unify_num_polys + 1])
        # Remove polynomials of the same domain
        poly_num_vars[unify_num_polys] = max(poly_num_vars[unify_num_polys], poly_num_vars[unify_num_polys + 1])
        del poly_num_vars[unify_num_polys + 1]
        del poly_domain_exponent[unify_num_polys + 1]
      unify_num_polys += 1
    max_num_vars = max(unify_sumcheck_num_vars_list)
    if len(unify_sumcheck_num_vars_list) > 1:
      unify_sumcheck_data_list.append(SumcheckData(unify_sumcheck_num_vars_list, max_num_vars))
    # At this point, all of the front `unify_num_polys` polynomials are on different domains and to be evaluated
    # Perform the rest of the WHIR round on the front `unify_num_polys` polynomials
    next_folding_factors = get_folding_factors(poly_domain_exponent, folding_factor, max_domain_exponent_fold)
    assert(len(next_folding_factors) == unify_num_polys)

    # Fold according to the difference in domain size
    for i in range(0, unify_num_polys):
      num_var = poly_num_vars[i]
      domain_exponent = poly_domain_exponent[i]
      next_folding_factor = next_folding_factors[i]
      assert(num_var >= next_folding_factor)
      fold_sumcheck_data_list.append(SumcheckData([num_var], next_folding_factor))
      # Query on the folded (main) polynomial
      query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_exponent, num_var), merkle_data_per_domain[0]))
      merkle_data_per_domain = merkle_data_per_domain[1:]
      if i == 0 and folded_poly_query:
        # Query on the new polynomial(s) to be added
        query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_exponent, num_var), merkle_data_per_domain[0]))
        merkle_data_per_domain = merkle_data_per_domain[1:]
    
    # Generate the next merkle tree for all of the folded polys
    next_num_vars = poly_num_vars[unify_num_polys - 1] - next_folding_factor
    next_domain_exponent = poly_domain_exponent[unify_num_polys - 1] - (next_folding_factor - folding_factor + 1)
    poly_num_vars = [next_num_vars] + poly_num_vars[unify_num_polys:]
    poly_domain_exponent = [next_domain_exponent] + poly_domain_exponent[unify_num_polys:]
    next_folding_factor = get_folding_factors(poly_domain_exponent, folding_factor, max_domain_exponent_fold)[0]

    if poly_num_vars[0] >= next_folding_factor:
      next_merkle = MerkleData(poly_domain_exponent[0], 1, next_folding_factor, False)
      merkle_data_per_domain = [next_merkle] + merkle_data_per_domain
      merkle_data_list.append(next_merkle)
    first_round = False

  return RawCost(merkle_data_list, unify_sumcheck_data_list, fold_sumcheck_data_list, query_data_list)

# Sort the polynomials from large to small
poly_num_vars.sort(reverse=True)
print(f"{len(poly_num_vars)} polys")
print(f"POLY NUM VARS: {poly_num_vars}, FOLD FACTOR: {folding_factor}")
print("\n--\nNO BATCH:")
no_batch_raw_cost = compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor)
no_batch_raw_cost.get_prover_verifier_cost()

print("\n--\nBATCH NO PAD:", end = ' ')
(_, num_domains, no_pad_raw_cost) = compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor)
print(f"{num_domains} starting domain(s)")
no_pad_raw_cost.get_prover_verifier_cost()
print("\n--\nBATCH ALL PAD:", end = ' ')
(_, num_domains, no_pad_raw_cost) = compute_batch_all_pad(soundness_type, pow_bits, poly_num_vars, folding_factor)
print(f"{num_domains} starting domain(s)")
no_pad_raw_cost.get_prover_verifier_cost()

print("\n--\nTHRESHOLD 25, DOMAIN_FOLD 1:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 25, 1)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nTHRESHOLD 50, DOMAIN_FOLD 1:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 50, 1)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nTHRESHOLD 100, DOMAIN_FOLD 1:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 100, 1)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()

print("\n--\nTHRESHOLD 25, DOMAIN_FOLD 2:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 25, 2)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nTHRESHOLD 50, DOMAIN_FOLD 2:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 50, 2)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nTHRESHOLD 100, DOMAIN_FOLD 2:", end = ' ')
(poly_domain_exponent, num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 100, 2)
print(f"{num_domains} starting domain(s): {poly_domain_exponent}")
threshold_raw_cost.get_prover_verifier_cost()