#pragma once
#include "config.h"
#include <blake3.h>

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