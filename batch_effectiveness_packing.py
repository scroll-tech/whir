# This program aims to discover the best batching strategy for prover and verifier given the number of variables of a list of polynomials
# It then compares the best batching strategy with no batch and optimal batch (cost to open the largest polynomial)
# Costs are divided into 3 categories:
# 1. Merkle Tree: the cost to construct a merkle tree, exclusive to the prover
# 2. Sumcheck: includes both the unifying sumcheck and folding sumcheck, measured in poly size (non-zero entries) for prover and number of rounds for the verifier
# 3. Query: number of queries per round, multiplied by the respective cost to the prover and the verifier

from math import log, ceil
from collections import Counter
# Soundness types
CONJECTURE_LIST = 0
PROVABLE_LIST = 1
UNIQUE_DECODING = 2

# --
# INPUTS
# poly_num_vars = [27, 26, 25, 24, 23, 22]
poly_num_vars = [27, 26, 23, 21]
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

def flatten(xss):
    return [x for xs in xss for x in xs]

class MerkleData:
  def __init__(self, domain_size, num_polys, folding_factor, is_starting_poly):
    assert(is_starting_poly or num_polys == 1)  # sanity check
    self.domain_size = domain_size
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
    print(f"FOLD SUMCHECK NUM ROUNDS: {len(self.fold_sumcheck_data_list)} x {self.fold_sumcheck_data_list[0].num_rounds} rounds each")
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
def get_num_queries(soundness_type, pow_bits, domain_size, num_vars):
  security_level = max(0, 100 - pow_bits)
  log_inv_rate = ceil(log(domain_size // (2 ** num_vars), 2))
  if soundness_type == UNIQUE_DECODING:
    rate = 1 / (1 << log_inv_rate)
    denom = log((0.5 * (1. + rate)), 2)
    return ceil(-1 * security_level / denom)
  elif soundness_type == PROVABLE_LIST:
    return ceil(2 * security_level / log_inv_rate)
  elif soundness_type == CONJECTURE_LIST:
    return ceil(security_level / log_inv_rate)

class PackedPoly:
  # A packedPoly contains two elements:
  # 1. number of variables
  # 2. a binary tree to denote the position of each poly within it
  def __init__(self, num_vars, empty_size, composition=None, next_entry=[]):
    self.num_vars = num_vars
    self.empty_size = empty_size
    self.composition = composition
    self.next_entry = next_entry # a list of binary to indicate the location of the next poly

  @classmethod
  def new_empty(cls, num_vars):
    return PackedPoly(num_vars, 2 ** num_vars)

  @classmethod
  def new_non_empty(cls, num_vars, empty_size, composition):
    return PackedPoly(num_vars, empty_size, composition)

  def fully_packed(self, max_num_vars):
    return self.empty_size == 0 and self.num_vars == max_num_vars

  # Add a new poly to the pack, return the new num vars
  # Assume that size of next_poly <= the smallest poly currently stored in self
  def add_next_poly(self, next_poly_num_vars):
    # The first poly must have the same num_vars as self.num_vars
    if self.composition == None:
      assert(self.num_vars == next_poly_num_vars)
    # Allocate new entries if full
    if self.fully_packed(self.num_vars):
      self.empty_size += 2 ** self.num_vars
      self.num_vars += 1
      self.composition = [self.composition, None]
      self.next_entry = [1]
    # Locate the opening
    next_opening_num_vars = self.num_vars - len(self.next_entry)
    assert(next_opening_num_vars >= next_poly_num_vars)
    while next_opening_num_vars > next_poly_num_vars:
      self.next_entry.append(0)
      next_opening_num_vars -= 1
    if len(self.next_entry) == 0:
      self.composition = next_poly_num_vars
    else:
      if self.composition == None:
        self.composition = [None, None]
      pointer = self.composition
      for index in self.next_entry[:-1]:
        if pointer[index] == None:
          pointer[index] = [None, None]
        pointer = pointer[index]
      pointer[self.next_entry[-1]] = next_poly_num_vars
    # Update next_entry:
    while len(self.next_entry) > 0 and self.next_entry[-1] == 1:
      self.next_entry = self.next_entry[:-1]
    if len(self.next_entry) > 0:
      self.next_entry[-1] = 1
    self.empty_size -= 2 ** next_poly_num_vars

  # Split the poly into left and right half
  # If any half can be expressed using fewer than num_vars - 1 variables, than make that reduction
  def split(self):
    # Only allows splitting if not fully packed
    assert(self.empty_size > 0)
    # By the above construction, the left half must be fully packed
    left_composition = self.composition[0]
    if type(left_composition) is list:
      left_composition = left_composition[:]
    left_poly = PackedPoly.new_non_empty(self.num_vars - 1, 0, left_composition)
    # Determine the size of the right poly
    right_num_vars = self.num_vars - 1
    right_empty_size = self.empty_size
    right_composition = self.composition[1]
    while type(right_composition) is list and len(right_composition) > 1 and right_composition[1] == None:
      right_num_vars -= 1
      right_empty_size -= 2 ** right_num_vars
      right_composition = right_composition[0]
    if type(right_composition) is list:
      right_composition = right_composition[:]
    right_poly = PackedPoly.new_non_empty(right_num_vars, right_empty_size, right_composition)
    return (left_poly, right_poly)

  # Obtain all the component polys
  def get_component_polys(self):
    # Compute the number of integers in self.composition using BFS
    subtree_list = [self.composition]
    components_list = []
    while len(subtree_list) > 0:
      next_subtree = subtree_list[0]
      subtree_list = subtree_list[1:]
      if type(next_subtree) is list:
        subtree_list.extend(next_subtree)
      elif type(next_subtree) is int:
        components_list.append(next_subtree)
    return components_list

# Compute packing
# Input a list of num_vars sorted in decreasing order (might contain repetition)
# The goal is to determine the best packing composition within (threshold)% of merkle leaf size blowup
def compute_packing(poly_num_vars, threshold):
  max_zero_size = int(sum([2 ** num_vars for num_vars in poly_num_vars]) * threshold / 100)
  max_pack_num_vars = poly_num_vars[0]
  packed_polys = [PackedPoly.new_empty(max_pack_num_vars)]
  for i in range(len(poly_num_vars)):
    packed_polys[-1].add_next_poly(poly_num_vars[i])
    if i < len(poly_num_vars) - 1 and packed_polys[-1].fully_packed(max_pack_num_vars):
      # Initialize the next packed_poly to have size poly_num_vars[i + 1]
      packed_polys.append(PackedPoly.new_empty(poly_num_vars[i + 1]))
  # Sanity check: all packed polys except the last one is full
  for p in packed_polys[:-1]:
    assert(p.fully_packed(max_pack_num_vars))
  # Repeatedly split the last poly until total_pack_size <= max_total_pack_size
  zero_size = packed_polys[-1].empty_size
  while zero_size > max_zero_size:
    assert(packed_polys[-1].empty_size > 0)
    (left_poly, right_poly) = packed_polys[-1].split()
    packed_polys = packed_polys[:-1] + [left_poly, right_poly]
    zero_size = packed_polys[-1].empty_size
  print("| ", end = "")
  for p in packed_polys:
    print(f"{" + ".join([str(n) for n in p.get_component_polys()])} ({p.num_vars})", end = " | ")
  return packed_polys

# Compute the cost if no batching occurs
def compute_no_batch(soundness_type, pow_bits, poly_num_vars, folding_factor):
  merkle_data_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  for num_var in poly_num_vars:
    domain_size = 2 * (2 ** num_var)
    prev_merkle_data = MerkleData(domain_size, 1, folding_factor, True)
    merkle_data_list.append(prev_merkle_data)
    while num_var >= folding_factor:
      fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
      query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), prev_merkle_data))
      num_var -= folding_factor
      if num_var >= folding_factor:
        domain_size //= 2
        prev_merkle_data = MerkleData(domain_size, 1, folding_factor, False)
        merkle_data_list.append(prev_merkle_data)
    # Final sumcheck
    fold_sumcheck_data_list.append(SumcheckData([num_var], num_var))
  return RawCost(merkle_data_list, [], fold_sumcheck_data_list, query_data_list)

def compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor):
  # Do not pad, compute domain size for each poly
  poly_domain_size = [2 * (2 ** num_var) for num_var in poly_num_vars]
  num_unique_domain_size = len(set(poly_domain_size))
  return (num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size))

def compute_batch_all_pad(soundness_type, pow_bits, poly_num_vars, folding_factor):
  # Pad every polynomial to the largest domain
  poly_domain_size = [2 * (2 ** poly_num_vars[0])] * len(poly_num_vars)
  num_unique_domain_size = 1
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

def compute_batch_pack_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, threshold):
  # Perform packing
  packed_polys = compute_packing(poly_num_vars, threshold)
  poly_num_vars = [p.num_vars for p in packed_polys]
  poly_domain_size = [2 * (2 ** num_var) for num_var in poly_num_vars]
  poly_components_list = [p.get_component_polys() for p in packed_polys]

  num_unique_domain_size = len(set(poly_domain_size))
  return (num_unique_domain_size, compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size, poly_components_list))

# Through packing, every poly might be consisted of component polys
# When unifying packed polys, the unifying sumcheck is performed on its component polys
def compute_batch(soundness_type, pow_bits, poly_num_vars, folding_factor, poly_domain_size, poly_components_list=[]):
  # If packing is not used, components of each poly is simply itself
  if poly_components_list == []:
    poly_components_list = [[n] for n in poly_num_vars]
  # One merkle tree for every starting domain
  unique_poly = Counter(poly_domain_size)
  # For queries
  merkle_data_per_domain = [MerkleData(poly[0], poly[1], folding_factor, True) for poly in unique_poly.items()]
  merkle_data_list = merkle_data_per_domain[:]
  unify_sumcheck_data_list = []
  fold_sumcheck_data_list = []
  query_data_list = []
  # Assume poly_num_vars is sorted
  # Remove entries from poly_num_vars and poly_domain_size as polys are unified
  poly_num_vars = poly_num_vars[:]
  poly_components_list = poly_components_list[:]
  poly_domain_size = poly_domain_size[:]

  # Check if this is the first round of a WHIR proof
  # If it is not, then if any new polys are added, need to query on the merkle tree of both the folded poly and new poly
  # If a polynomial is completely folded and there are still (smaller) polynomials remaining, the next round is "first round" as well
  first_round = True
  while len(poly_num_vars) > 0:
    # If num_vars < folding_factor, this polynomial reaches the final round
    if len(poly_num_vars) > 0 and poly_num_vars[0] < folding_factor:
      # Final sumcheck
      fold_sumcheck_data_list.append(SumcheckData([poly_num_vars[0]], poly_num_vars[0]))
      poly_num_vars = poly_num_vars[1:]
      poly_components_list = poly_components_list[1:]
      poly_domain_size = poly_domain_size[1:]
      first_round = True
    if len(poly_num_vars) == 0:
      break
    
    # Find out how many polynomials have the same domain
    unify_sumcheck_num_polys = 0
    # Perform unifying sumcheck on all polys of the same domain size
    while unify_sumcheck_num_polys < len(poly_num_vars) and poly_domain_size[unify_sumcheck_num_polys] == poly_domain_size[0]:
      unify_sumcheck_num_polys += 1
    unify_sumcheck_num_vars_list = flatten(poly_components_list[:unify_sumcheck_num_polys])
    if len(unify_sumcheck_num_vars_list) > 1:
      max_num_vars = max(poly_num_vars[:unify_sumcheck_num_polys]) # Unified poly has same num_vars as the largest packed poly
      unify_sumcheck_data_list.append(SumcheckData(unify_sumcheck_num_vars_list, max_num_vars))
      # Remove all polynomials of the same domain
      poly_num_vars = [max_num_vars] + poly_num_vars[unify_sumcheck_num_polys:] # New num_vars
      poly_components_list = [[max_num_vars]] + poly_components_list[unify_sumcheck_num_polys:]
      poly_domain_size = poly_domain_size[:1] + poly_domain_size[unify_sumcheck_num_polys:]
    
    # Perform the rest of the WHIR round on the poly[0]
    num_var = poly_num_vars[0]
    domain_size = poly_domain_size[0]
    assert(num_var >= folding_factor)
    fold_sumcheck_data_list.append(SumcheckData([num_var], folding_factor))
    # Query on the folded (main) polynomial
    query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), merkle_data_per_domain[0]))
    merkle_data_per_domain = merkle_data_per_domain[1:]
    if not first_round and unify_sumcheck_num_polys > 1:
      # Query on the new polynomial(s) to be added
      query_data_list.append(QueryData(get_num_queries(soundness_type, pow_bits, domain_size, num_var), merkle_data_per_domain[0]))
      merkle_data_per_domain = merkle_data_per_domain[1:]
    
    poly_num_vars[0] -= folding_factor
    poly_components_list[0][0] -= folding_factor
    if poly_num_vars[0] >= folding_factor:
      poly_domain_size[0] //= 2
      next_merkle = MerkleData(poly_domain_size[0], 1, folding_factor, False)
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
(num_domains, no_pad_raw_cost) = compute_batch_no_pad(soundness_type, pow_bits, poly_num_vars, folding_factor)
print(f"{num_domains} starting domain(s)")
no_pad_raw_cost.get_prover_verifier_cost()
print("\n--\nBATCH ALL PAD:", end = ' ')
(num_domains, no_pad_raw_cost) = compute_batch_all_pad(soundness_type, pow_bits, poly_num_vars, folding_factor)
print(f"{num_domains} starting domain(s)")
no_pad_raw_cost.get_prover_verifier_cost()

"""
print("\n--\nPAD THRESHOLD 25:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 25)
print(f"{num_domains} starting domain(s)")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nPAD THRESHOLD 50:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 50)
print(f"{num_domains} starting domain(s)")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nPAD THRESHOLD 100:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pad_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 100)
print(f"{num_domains} starting domain(s)")
threshold_raw_cost.get_prover_verifier_cost()
"""

print("\n--\nPACK THRESHOLD 25:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pack_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 25)
print(f"{num_domains} starting domain(s)")
threshold_raw_cost.get_prover_verifier_cost()
print("\n--\nPACK THRESHOLD 50:", end = ' ')
(num_domains, threshold_raw_cost) = compute_batch_pack_threshold(soundness_type, pow_bits, poly_num_vars, folding_factor, 50)
print(f"{num_domains} starting domain(s)")
threshold_raw_cost.get_prover_verifier_cost()