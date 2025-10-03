#pragma once

#include <vector>

#include <blake3.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <spdlog/spdlog.h>

#include "config.h"

// Sampling with specified intersection size
void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts);

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
u64 fast_pow(u64 base, u64 exp);
u64 combination(u64 n, u64 k);

// delta internal Align Top
u64 align_to_interval(u64 delta);

struct Monty25519Hash {
  std::size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    std::array<u8, 32> bytes;
    point.toBytes(bytes.data()); // Assuming Monty25519 provides toBytes method
    return std::hash<std::string_view>()(
        std::string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};

vector<u64> get_phi_dim_optimized(const vector<pt> &pts, u64 delta);

inline block get_value_fmap_opprf(u64 i, string prefix, u64 j, string prefix2) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &i, sizeof(i));
  blake3_hasher_update(&hasher, prefix.data(), prefix.size());
  blake3_hasher_update(&hasher, &j, sizeof(j));
  blake3_hasher_update(&hasher, prefix2.data(), prefix2.size());

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline void padding_blocks(vector<block> &vals, u64 count) {
  if (vals.size() >= count) {
    return;
  }

  auto padding_count = count - vals.size();
  auto original_size = vals.size();

  PRNG prng((block(oc::sysRandomSeed())));

  vals.resize(count);
  prng.get(vals.data() + original_size, padding_count);
}