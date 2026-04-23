#pragma once

#include <vector>

#include <blake3.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <ipcl/bignum.h>
#include <spdlog/spdlog.h>

#include "config.h"

// Sampling with specified intersection size
void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts, bool same = false);

// Helper functions required for spatial hashing
pt cell(const pt &p, u64 dim, u64 side_len);
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen);

u64 l1_dist(const pt &p1, const pt &p2, u64 dim);
u64 l2_dist(const pt &p1, const pt &p2, u64 dim);
u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim);

u64 get_position(const pt &cross_point, const pt &source_point, u64 dim);
vector<pt> intersection(const pt &p, u64 metric, u64 dim, u64 delta,
                        u64 sidelen, u64 blk_cells, u64 delta_l2);

// math compute
/// Calculate the combination number
///
/// Calculate the number of combinations for choosing `k` elements from `n`
/// elements.
///
/// # Parameters
/// - `n`: Total number of elements
/// - `k`: Number of elements to choose
///
/// # Returns
/// Returns a value of type `u64` representing the number of combinations.
/// Returns 0 if `k` is greater than `n`.
template <typename T> T combination(T n, T k) {
  if (k > n)
    return 0;
  if (k > n - k)
    k = n - k; // C(n, k) == C(n, n-k), do less computation
  T result = 1;
  for (T i = 0; i < k; ++i) {
    result = result * (n - i) / (i + 1);
  }
  return result;
}

// fast exponentiation
template <typename T> T fast_pow(u64 base, u64 exp) {
  T result = 1;
  while (exp > 0) {
    if (exp & 1)
      result *= base;
    base *= base;
    exp >>= 1;
  }
  return result;
}

struct Monty25519Hash {
  size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    array<u8, 32> bytes;
    point.toBytes(bytes.data()); // Assuming Monty25519 provides toBytes method
    return hash<string_view>()(
        string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};

inline block get_blk_from_cell(const vector<u64> &cell) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, cell.data(), cell.size() * sizeof(u64));
  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}