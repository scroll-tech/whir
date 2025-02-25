# This program aims to discover the best batching strategy for prover and verifier given the number of variables of a list of polynomials
# It then compares the best batching strategy with no batch and optimal batch (cost to open the largest polynomial)
# Costs are divided into 3 categories:
# 1. Merkle Tree: the cost to construct a merkle tree, exclusive to the prover
# 2. Sumcheck: includes both the unifying sumcheck and folding sumcheck, measured in poly size (non-zero entries) for prover and number of rounds for the verifier
# 3. Query: number of queries per round, multiplied by the respective cost to the prover and the verifier

from math import log, ceil

class SumcheckData:
  def __init__(self, num_vars_list, num_rounds):
    self.num_vars_list = num_vars_list # num of vars of all the polynomials involved in the sumcheck
    self.num_rounds = num_rounds

class QueryData:
  def __init__(self, num_queries, folded_domain_size):
    self.num_queries = num_queries
    self.folded_domain_size = folded_domain_size

class RawCost:
  # domain_size_list includes the domain size of EVERY TREE (same poly different round)
  # query_data_list includes EVERY QUERY
  def __init__(self, folding_factor, domain_size_list, unify_sumcheck_data_list, fold_sumcheck_data_list, query_data_list):
    self.folding_factor = folding_factor
    self.domain_size_list = domain_size_list
    self.unify_sumcheck_data_list = unify_sumcheck_data_list
    self.fold_sumcheck_data_list = fold_sumcheck_data_list
    self.query_data_list = query_data_list

  def get_prover_verifier_cost(self):
    # Overview
    print("MERKLE NUM LEAFS: ", self.domain_size_list)
    print("UNIFY SUMCHECK NUM ROUNDS: ", [d.num_rounds for d in self.unify_sumcheck_data_list])
    print(f"FOLD SUMCHECK NUM ROUNDS: {len(self.fold_sumcheck_data_list)} x {self.fold_sumcheck_data_list[0].num_rounds} rounds each")
    print("NUM QUERIES: ", [q.num_queries for q in self.query_data_list])

    # Merkle
    print("--")
    total_merkle_cost = 0
    for d in self.domain_size_list:
      num_leafs = d // self.folding_factor
      # Total size is leaf_size + num_leafs - 1
      total_merkle_cost += d + num_leafs - 1
    print("TOTAL MERKLE TREE SIZE: ", total_merkle_cost)

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
    total_query_depth = 0
    for q in self.query_data_list:
      total_query_depth += q.num_queries * ceil(log(q.folded_domain_size, 2))
    print("TOTAL QUERY SIZE: ", total_query_depth)


# Soundness types
CONJECTURE_LIST = 0
PROVABLE_LIST = 1
UNIQUE_DECODING = 2

# Compute number of queries
def get_num_queries(soundness_type, pow_bits, domain_size, num_vars):
  security_level = max(0, 32 - pow_bits)
  log_inv_rate = ceil(log(domain_size // (2 ** num_vars), 2))
  if soundness_type == UNIQUE_DECODING:
    rate = 1 / (1 << log_inv_rate)
    denom = log((0.5 * (1. + rate)), 2)
    return ceil(-1 * security_level / denom)
  elif soundness_type == PROVABLE_LIST:
    return ceil(2 * security_level / log_inv_rate)
  elif soundness_type == CONJECTURE_LIST:
    return ceil(security_level / log_inv_rate)

# Compute the cost if no batching occurs
def compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor):
  domain_size_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  for num_var in poly_num_vars:
    domain_size = 2 * (2 ** num_var)
    while num_var >= folding_factor:
      domain_size_list.append(domain_size)
      fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
      query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), domain_size // (2 ** folding_factor)))
      num_var -= folding_factor
      domain_size //= 2
  return RawCost(folding_factor, domain_size_list, [], fold_sumcheck_data_list, query_data_list)

def compute_optimal(soundness_type, pow_bits, poly_num_vars, folding_factor):
  domain_size_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  # Assume poly_num_vars is sorted
  num_var = poly_num_vars[0]
  domain_size = 2 * (2 ** num_var)
  while num_var >= folding_factor:
    domain_size_list.append(domain_size)
    fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
    query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), domain_size // (2 ** folding_factor)))
    num_var -= folding_factor
    domain_size //= 2
  return RawCost(folding_factor, domain_size_list, [], fold_sumcheck_data_list, query_data_list)

def compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor):
  # Compute domain size for each poly
  poly_domain_size = [2 * (2 ** num_var) for num_var in poly_num_vars]
  num_unique_domain_size = len(set(poly_domain_size))
  return (num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size))

def compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, threshold):
  # The prover is allowed extra (threshold)% of starting domain size
  poly_domain_size = [2 * (2 ** num_var) for num_var in poly_num_vars]
  target_domain_size = int(sum(poly_domain_size) * (1 + threshold / 100))
  # Repeatedly increase the domain size of the smallest polys
  next_entry_to_pad = len(poly_domain_size) - 1
  while next_entry_to_pad > 0 and poly_domain_size[next_entry_to_pad - 1] == poly_domain_size[next_entry_to_pad]:
    next_entry_to_pad -= 1
  prev_poly_domain_size = poly_domain_size[:]
  while next_entry_to_pad > 0 and sum(poly_domain_size) < target_domain_size:
    prev_poly_domain_size = poly_domain_size[:]
    # Pad domain of every poly >= next_entry_to_pad to poly_domain_size[next_entry_to_pad - 1]
    for i in range(next_entry_to_pad, len(poly_domain_size)):
      poly_domain_size[i] = poly_domain_size[next_entry_to_pad - 1]
    # Find new next_entry_to_pad
    while next_entry_to_pad > 0 and poly_domain_size[next_entry_to_pad - 1] == poly_domain_size[next_entry_to_pad]:
      next_entry_to_pad -= 1
  # Revert to the domain size and next pad before threshold
  poly_domain_size = prev_poly_domain_size
  num_unique_domain_size = len(set(poly_domain_size))
  return (num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size))

def compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size):
  # Do not perform any padding, batch in each polynomial when its their turn
  domain_size_list = []
  unify_sumcheck_data_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  # Assume poly_num_vars is sorted
  # Remove entries from poly_num_vars and poly_domain_size as polys are unified
  poly_num_vars = poly_num_vars[:]
  poly_domain_size = poly_domain_size[:]
  while len(poly_num_vars) > 0:
    # If num_vars < folding_factor, this polynomial reaches the final round
    while len(poly_num_vars) > 0 and poly_num_vars[0] < folding_factor:
      poly_num_vars = poly_num_vars[1:]
      poly_domain_size = poly_domain_size[1:]
    if len(poly_num_vars) == 0:
      break
    # Perform unifying sumcheck on all polys of the same domain size
    if len(poly_num_vars) > 1 and poly_domain_size[0] == poly_domain_size[1]:
      # Find out how many polynomials have the same domain
      unify_sumcheck_num_polys = 2
      while unify_sumcheck_num_polys < len(poly_num_vars) and poly_domain_size[unify_sumcheck_num_polys] == poly_domain_size[0]:
        unify_sumcheck_num_polys += 1
      unify_sumcheck_num_vars_list = poly_num_vars[:unify_sumcheck_num_polys]
      # It always holds that num_vars[0] <= num_vars[1] == num_vars[2] == ...
      unify_sumcheck_data_list.append(SumcheckData(unify_sumcheck_num_vars_list, unify_sumcheck_num_vars_list[1]))
      # Remove all polynomials of the same domain, num_vars of the unified polynomial is num_vars[1]
      poly_num_vars = poly_num_vars[1:2] + poly_num_vars[unify_sumcheck_num_polys:] # New num_vars 
      poly_domain_size = poly_domain_size[:1] + poly_domain_size[unify_sumcheck_num_polys:]
    # Perform the rest of the WHIR round on the first variable
    num_var = poly_num_vars[0]
    domain_size = poly_domain_size[0]
    assert(num_var >= folding_factor)
    domain_size_list.append(domain_size)
    fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
    query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), domain_size // (2 ** folding_factor)))
    poly_num_vars[0] -= folding_factor
    poly_domain_size[0] //= 2

  return RawCost(folding_factor, domain_size_list, unify_sumcheck_data_list, fold_sumcheck_data_list, query_data_list)

poly_num_vars = [27, 26, 25, 24, 23, 22]
folding_factor = 4
soundness_type = CONJECTURE_LIST
pow_bits = 0

# Sort the polynomials from large to small
poly_num_vars.sort(reverse=True)
print(f"{len(poly_num_vars)} polys")
print(f"POLY NUM VARS: {poly_num_vars}, FOLD FACTOR: {folding_factor}")
print("\n--\nNO BATCH:")
no_batch_raw_cost = compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor)
no_batch_raw_cost.get_prover_verifier_cost()
print("\n--\nTHEORETICAL OPTIMAL:")
optimal_raw_cost = compute_optimal(soundness_type, pow_bits, poly_num_vars, folding_factor)
optimal_raw_cost.get_prover_verifier_cost()

print("\n--\nBATCH NO PAD:", end = ' ')
(num_domains, no_pad_raw_cost) = compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor)
print(f"{num_domains} starting domains")
no_pad_raw_cost.get_prover_verifier_cost()

print("\n--\nBATCH THRESHOLD 25:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 25)
print(f"{num_domains} starting domains")
threshold_raw_cost.get_prover_verifier_cost()

print("\n--\nBATCH THRESHOLD 50:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 50)
print(f"{num_domains} starting domains")
threshold_raw_cost.get_prover_verifier_cost()

print("\n--\nBATCH THRESHOLD 100:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 100)
print(f"{num_domains} starting domains")
threshold_raw_cost.get_prover_verifier_cost()