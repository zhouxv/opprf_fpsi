#pragma once
#include "config.h"

#include <array>
#include <vector>

#include <coproto/Common/macoro.h>
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <spdlog/spdlog.h>

#include "opprf/Defines.h"
#include "pis_new/equal.h"
#include "pis_new/triple.h"

vector<vector<u64>> compute_split_index(const u64 eles_size);

template <typename T>
cp::task<vector<u64>> Batch_PIS_recv_new(vector<T> &eles, const u64 batch_size,
                                         const u64 batch_num,
                                         cp::Socket &socket) {
  // Check input size
  assert(
      eles.size() == batch_num * batch_size &&
      "Input size does not match batch_size * batch_num in Batch_PIS_recv_new");
  // Check batch_size is power of 2
  assert((batch_size & (batch_size - 1)) == 0 &&
         "batch_size is not power of 2 in Batch_PIS_recv_new");

  /*
  PIS step 1
  */
  u64 bit_length = sizeof(T) * 8;
  auto input_bits = toBitVector(oc::span<T>(eles), bit_length);
  u64 num_triples = batch_num * batch_size * bit_length;

  Triples triples(num_triples);
  BitVector eqRes0;

  // spdlog::debug("[Batch_PIS_recv] batch_num {} ; batch_size {} ; input_bits
  // {} ; num_triples: {}",      batch_num, batch_size, input_bits.size(),
  // num_triples);
  co_await triples.gen0(socket);
  co_await eq0(socket, bit_length, triples, input_bits, eqRes0);

  BitVector s0;
  s0.resize(batch_num, 0);
  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      s0[i] = s0[i] ^ eqRes0[i * batch_size + j];
    }
  }

  // spdlog::debug("[Batch_PIS_recv] step 1 finished.");

  /*
  PIS step 2
  */
  vector<block> s(batch_num, ZeroBlock);
  auto indexs = compute_split_index(batch_size);
  auto psm_num = indexs.size();
  auto psm_size = indexs[0].size();

  for (u64 i = 0; i < batch_num; i++) {
    auto batch_index = i * batch_size;
    block s_(ZeroBlock);
    for (u64 m = 0; m < psm_num; m++) {
      bool tmp = 0;
      for (u64 n = 0; n < psm_size; n++) {
        tmp = tmp ^ eqRes0[batch_index + indexs[m][n]];
      }
      s_ = s_ | block(tmp << m);
    }
    s[i] = s_;
  }

  // spdlog::debug("[Batch_PIS_recv] step 2 finished.");

  /*
  PIS step 3
  batch process
  */
  u64 numOTs = batch_num;
  PRNG prng(oc::sysRandomSeed());

  // SilentOt recv
  oc::SilentOtExtReceiver recv;
  recv.configure(numOTs, 2, 1, oc::SilentSecType::SemiHonest,
                 SdNoiseDistribution::Regular, oc::DefaultMultType);

  //  gen baseOT
  co_await recv.genBaseCors(prng, socket);

  // spdlog::debug("[Batch_PIS_recv] Silent OT base gen finished.");

  vector<block> recvMsg(numOTs);

  co_await recv.receive(s0, recvMsg, prng, socket);

  vector<block> mask_msg_0(numOTs);
  vector<block> mask_msg_1(numOTs);
  co_await socket.recv(mask_msg_0);
  co_await socket.recv(mask_msg_1);

  for (u64 i = 0; i < numOTs; i++) {
    recvMsg[i] =
        (s0[i]) ? (recvMsg[i] ^ mask_msg_1[i]) : (recvMsg[i] ^ mask_msg_0[i]);
  }

  vector<u64> pis_res(batch_num, 0);
  block block_mask = block((u64)(1ull << psm_num) - 1);
  for (u64 i = 0; i < batch_num; i++) {
    pis_res[i] = ((recvMsg[i] ^ s[i]) & block_mask).get<u64>(0);
  }

  // spdlog::debug("[Batch_PIS_recv] step 3 finished.");

  co_return pis_res;
}

template <typename T>
cp::task<void> Batch_PIS_send_new(vector<T> &datas, const u64 batch_size,
                                  const u64 batch_num, cp::Socket &socket) {
  // Check input size
  assert(datas.size() == batch_num &&
         "Input size does not match batch_num in Batch_PIS_send_new");
  // check batch_size is power of 2
  assert((batch_size & (batch_size - 1)) == 0 &&
         "batch_size is not power of 2 in Batch_PIS_send_new");

  /*
  PIS step 1
  */
  u64 bit_length = sizeof(T) * 8;
  u64 num_triples = batch_num * batch_size * bit_length;

  vector<T> datas_copy(batch_num * batch_size);

  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      datas_copy[i * batch_size + j] = datas[i];
    }
  }

  auto input_bits = toBitVector(oc::span<T>(datas_copy), bit_length);
  input_bits = ~input_bits;

  Triples triples(num_triples);
  BitVector eqRes1;

  // spdlog::debug("[Batch_PIS_send] batch_num {} ; batch_size {} ; input_bits
  // {} "
  //               "; num_triples: {}",
  //               batch_num, batch_size, input_bits.size(), num_triples);

  co_await triples.gen1(socket);
  co_await eq1(socket, bit_length, triples, input_bits, eqRes1);

  BitVector t0;
  t0.resize(batch_num, 0);

  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      t0[i] = t0[i] ^ eqRes1[i * batch_size + j];
    }
  }

  // spdlog::debug("[Batch_PIS_send] step 1 finished.");

  /*
  PIS step 2
  */
  vector<block> t(batch_num, ZeroBlock);
  auto indexs = compute_split_index(batch_size);
  auto psm_num = indexs.size();
  auto psm_size = indexs[0].size();

  for (u64 i = 0; i < batch_num; i++) {
    auto batch_index = i * batch_size;
    block t_(ZeroBlock);
    for (u64 m = 0; m < psm_num; m++) {
      bool tmp = 0;
      for (u64 n = 0; n < psm_size; n++) {
        tmp = tmp ^ eqRes1[batch_index + indexs[m][n]];
      }
      t_ = t_ | block(tmp << m);
    }
    t[i] = t_;
  }

  // spdlog::debug("[Batch_PIS_send] step 2 finished.");

  /*
  PIS step 3
  batch process
  */
  PRNG prng(oc::sysRandomSeed());
  vector<array<block, 2>> pis_msg(batch_num);

  // (t0 ^ 1) * r
  for (u64 i = 0; i < batch_num; i++) {
    auto tmp_mask = t0[i] ^ 1;
    oc::block r = prng.get<block>();
    auto q0 = (tmp_mask) ? r ^ t[i] : t[i];
    auto q1 = r ^ q0;
    pis_msg[i] = {q0, q1};
  }

  u64 numOTs = batch_num;

  // SilentOt sender
  oc::SilentOtExtSender sender;
  sender.configure(numOTs, 2, 1, oc::SilentSecType::SemiHonest,
                   SdNoiseDistribution::Regular, oc::DefaultMultType);

  //  gen baseOT
  co_await sender.genBaseCors({}, prng, socket);

  // spdlog::debug("[Batch_PIS_send] Silent OT base gen finished.");

  vector<array<block, 2>> sendMsg(numOTs);
  vector<block> half_sendMsg_0(numOTs);
  vector<block> half_sendMsg_1(numOTs);

  // random OT send
  co_await sender.send(sendMsg, prng, socket);

  // random OT -> OT
  for (u64 i = 0; i < numOTs; i++) {
    half_sendMsg_0[i] = pis_msg[i][0] ^ sendMsg[i][0];
    half_sendMsg_1[i] = pis_msg[i][1] ^ sendMsg[i][1];
  }
  co_await socket.send(half_sendMsg_0);
  co_await socket.send(half_sendMsg_1);

  // spdlog::debug("[Batch_PIS_send] step 3 finished.");
}