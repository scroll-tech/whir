# This program aims to discover the best batching strategy for prover and verifier given the number of variables of a list of polynomials
# It then compares the best batching strategy with no batch and optimal batch (cost to open the largest polynomial)
# Costs are divided into 3 categories:
# 1. Merkle Tree: the cost to construct a merkle tree, exclusive to the prover
# 2. Sumcheck: includes both the unifying sumcheck and folding sumcheck, measured in poly size (non-zero entries) for prover and number of rounds for the verifier
# 3. Query: number of queries per round, multiplied by the respective cost to the prover and the verifier

from math import log, ceil

class SumcheckData:
  def __init__(self, num_vars, num_rounds):
    self.num_vars = num_vars
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
    print("UNIFY SUMCHECK NUM VARS: ", [d.num_vars for d in self.unify_sumcheck_data_list])
    print("FOLD SUMCHECK NUM VARS: ", [d.num_vars for d in self.fold_sumcheck_data_list])
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
      poly_size = 2 ** s.num_vars
      for _ in range(0, s.num_rounds):
        total_sumcheck_size += poly_size
        poly_size //= 2
    print("TOTAL SUMCHECK COMPUTATION SIZE: ", total_sumcheck_size)
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
      fold_sumcheck_data_list.append(SumcheckData(num_var, folding_factor))
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
    fold_sumcheck_data_list.append(SumcheckData(num_var, folding_factor))
    query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), domain_size // (2 ** folding_factor)))
    num_var -= folding_factor
    domain_size //= 2
  return RawCost(folding_factor, domain_size_list, [], fold_sumcheck_data_list, query_data_list)

poly_num_vars = [3, 5, 4]
folding_factor = 2
soundness_type = CONJECTURE_LIST
pow_bits = 0

# Sort the polynomials from large to small
poly_num_vars.sort(reverse=True)
print("\n--\nNO BATCH:")
no_batch_raw_cost = compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor)
no_batch_raw_cost.get_prover_verifier_cost()
print("\n--\nOPTIMAL:")
optimal_raw_cost = compute_optimal(soundness_type, pow_bits, poly_num_vars, folding_factor)
optimal_raw_cost.get_prover_verifier_cost()