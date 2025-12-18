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
u64 fast_pow(u64 base, u64 exp);
u64 combination(u64 n, u64 k);

// helper functions for block vector manipulation
vector<block> flattenBlocks(const vector<vector<block>> &blockData);
vector<vector<block>> chunkFixedSizeBlocks(const vector<block> &flatData,
                                           size_t chunk_size);

struct Monty25519Hash {
  size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    array<u8, 32> bytes;
    point.toBytes(bytes.data()); // Assuming Monty25519 provides toBytes method
    return hash<string_view>()(
        string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};

vector<u64> get_phi_dim_optimized(const vector<pt> &pts, u64 delta);

// converse Ciphertext -> vector<block>
vector<block> bignumer_to_block_vector(const BigNumber &bn);

// converse vector<block> -> Ciphertext
BigNumber block_vector_to_bignumer(const std::vector<block> &ct);

// Helper functions for OKVS and OPPRF key generation
inline block get_fmap_opprf_key(u64 i_star, u64 x_i_star_s1, u64 i,
                                u64 x_i_s2) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &i_star, sizeof(i_star));
  blake3_hasher_update(&hasher, &x_i_star_s1, sizeof(x_i_star_s1));
  blake3_hasher_update(&hasher, &i, sizeof(i));
  blake3_hasher_update(&hasher, &x_i_s2, sizeof(x_i_s2));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

// Helper functions for OKVS and OPPRF key generation
inline block get_fmap_okvs_key(u64 dim_index, u64 blk) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim_index, sizeof(dim_index));
  blake3_hasher_update(&hasher, &blk, sizeof(blk));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

// Pad datas to specified length
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

// Pad datas to specified length
inline void padding_keys(vector<block> &keys, u64 count) {
  if (keys.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  while (keys.size() < count) {
    keys.push_back(prng.get<block>());
  }
}

// Pad datas to specified length
inline void padding_values(vector<vector<block>> &values, u64 count,
                           u64 blk_size) {
  if (values.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  vector<block> blks(blk_size, ZeroBlock);

  while (values.size() < count) {
    prng.get(blks.data(), blk_size);
    values.push_back(blks);
  }
}