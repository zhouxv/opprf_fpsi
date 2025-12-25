#include "data_conversion_util.h"

vector<block> bignumer_to_block_vector(const BigNumber &bn) {
  vector<u32> ct;
  bn.num2vec(ct);

  vector<block> cipher_block(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock);

  PRNG prng(oc::sysRandomSeed());

  if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] = prng.get<block>();
    }
  } else {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] =
          block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i])));
    }
  }

  return cipher_block;
}

BigNumber block_vector_to_bignumer(const vector<block> &ct) {
  vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);
  u32 temp[4];
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    memcpy(temp, ct[i].data(), 16);

    ct_u32[4 * i] = temp[0];
    ct_u32[4 * i + 1] = temp[1];
    ct_u32[4 * i + 2] = temp[2];
    ct_u32[4 * i + 3] = temp[3];
  }
  BigNumber bn = BigNumber(ct_u32.data(), ct_u32.size());
  return bn;
}

vector<block> bignumers_to_block_vector(const vector<BigNumber> &bns) {
  auto count = bns.size();
  vector<block> cipher_block;
  cipher_block.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * count);

  vector<u32> ct;
  ct.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4);

  PRNG prng(oc::sysRandomSeed());

  for (const auto &bn : bns) {
    bn.num2vec(ct);

    if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(prng.get<block>());
      }
    } else {
      // NOTES: Little-endian block construction, if it's big-endian, need to
      // modify
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(
            block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                  ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i]))));
      }
    }
    ct.clear();
  }

  return cipher_block;
}

// used for homo mul
vector<BigNumber> block_vector_to_bignumers(const vector<block> &ct,
                                            const u64 &bn_num,
                                            std::shared_ptr<BigNumber> nsq) {
  vector<BigNumber> bns;

  vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < bn_num; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()) % (*nsq));
  }

  return bns;
}

// used for homo add
vector<BigNumber> block_vector_to_bignumers(const vector<block> &ct,
                                            const u64 &bn_num) {
  vector<BigNumber> bns;

  vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < bn_num; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()));
  }

  return bns;
}