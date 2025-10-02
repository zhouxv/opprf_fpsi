#pragma once

#include "config.h"
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>
#include <vector>

struct BatchPisRecvResult {
  BitVector s0;
  vector<block> s;
};

struct BatchPisSenderResult {
  vector<array<block, 2>> pis_msg;
};

coproto::task<BatchPisRecvResult>
Batch_PIS_recv(vector<u64> &eles, const u64 batch_size,
               const vector<vector<u64>> &indexs, coproto::Socket &socket);

coproto::task<BatchPisSenderResult>
Batch_PIS_send(vector<u64> &datas, u64 batch_size,
               const vector<vector<u64>> &indexs, coproto::Socket &socket);

vector<block> PIS_recv_KKRT_batch(BitVector &s0, coproto::Socket &socket);

void PIS_sender_KKRT_batch(vector<array<block, 2>> &pis_msg,
                           coproto::Socket &socket);

vector<vector<u64>> compute_split_index(const u64 eles_size);

vector<vector<u64>> split_vertor(vector<u64> &eles,
                                 const vector<vector<u64>> &eles_index);