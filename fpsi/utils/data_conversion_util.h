#pragma once
#include "config.h"
#include <ipcl/bignum.h>

// converse Ciphertext -> vector<block>
vector<block> bignumer_to_block_vector(const BigNumber &bn);

// converse vector<block> -> Ciphertext
BigNumber block_vector_to_bignumer(const vector<block> &ct);

// converse vector<BigNumber> <-> blocks
vector<block> bignumers_to_block_vector(const vector<BigNumber> &bns);

// converse blocks <-> vector<BigNumber>
vector<BigNumber> block_vector_to_bignumers(const vector<block> &ct,
                                            const u64 &bn_num,
                                            std::shared_ptr<BigNumber> nsq);

// converse blocks <-> vector<BigNumber>
vector<BigNumber> block_vector_to_bignumers(const vector<block> &ct,
                                            const u64 &bn_num);