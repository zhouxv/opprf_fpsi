#include <array>
#include <vector>

#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <spdlog/spdlog.h>

#include "pis_new/batch_pis.h"
#include "pis_new/equal.h"
#include "pis_new/triple.h"

coproto::task<BatchPisRecvResult>
Batch_PIS_recv(vector<u64> &eles, const u64 batch_size,
               const vector<vector<u64>> &indexs, coproto::Socket &socket) {
  /*
  PIS step 1
  */
  u64 bit_length = 64;
  auto input_bits = toBitVector(eles, bit_length);
  u64 batch_num = eles.size() / batch_size;
  u64 num_triples = eles.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes0;

  spdlog::debug("[Batch_PIS_recv] batch_num {} ; batch_size {} ; input_bits {} "
                "; num_triples: {}",
                batch_num, batch_size, input_bits.size(), num_triples);
  co_await triples.gen0(socket);
  co_await eq0(socket, bit_length, triples, input_bits, eqRes0);

  BitVector s0;
  s0.resize(batch_num, 0);
  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      s0[i] = s0[i] ^ eqRes0[i * batch_size + j];
    }
  }

  /*
  PIS step 2
  */
  vector<block> s(batch_num, ZeroBlock);
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

  // for (auto a : s) {
  //   spdlog::debug("s: {}", bitset<64>(a.get<u64>(0)).to_string());
  // }

  /*
  PIS step 3
  batch process
  */
  BatchPisRecvResult result;
  result.s0 = std::move(s0);
  result.s = std::move(s);

  co_return result;
}

coproto::task<BatchPisSenderResult>
Batch_PIS_send(vector<u64> &datas, u64 batch_size,
               const vector<vector<u64>> &indexs, coproto::Socket &socket) {
  /*
  PIS step 1
  */
  u64 bit_length = 64;
  u64 batch_num = datas.size();
  u64 num_triples = batch_num * batch_size * bit_length;

  vector<u64> datas_copy(batch_num * batch_size);

  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      datas_copy[i * batch_size + j] = datas[i];
    }
  }

  auto input_bits = toBitVector(datas_copy, bit_length);
  input_bits = ~input_bits;

  Triples triples(num_triples);
  BitVector eqRes1;

  spdlog::debug("[Batch_PIS_send] batch_num {} ; batch_size {} ; input_bits {} "
                "; num_triples: {}",
                batch_num, batch_size, input_bits.size(), num_triples);

  co_await triples.gen1(socket);
  co_await eq1(socket, bit_length, triples, input_bits, eqRes1);

  BitVector t0;
  t0.resize(batch_num, 0);

  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      t0[i] = t0[i] ^ eqRes1[i * batch_size + j];
    }
  }

  /*
  PIS step 2
  */

  vector<block> t(batch_num, ZeroBlock);
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

  // for (auto a : t) {
  //   spdlog::debug("t: {}", bitset<64>(a.get<u64>(0)).to_string());
  // }

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

  BatchPisSenderResult result;
  result.pis_msg = std::move(pis_msg);

  co_return result;
}

vector<block> PIS_recv_KKRT_batch(BitVector &s0, coproto::Socket &socket) {
  u64 numOTs = s0.size();
  PRNG prng(oc::sysRandomSeed());

  // baseOT send
  osuCrypto::DefaultBaseOT baseOTs;
  vector<array<block, 2>> baseSend(128);
  prng.get((u8 *)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
  auto p = baseOTs.send(baseSend, prng, socket);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp recv
  IknpOtExtReceiver recv;
  recv.setBaseOts(baseSend);

  vector<block> recvMsg;
  recvMsg.resize(numOTs);

  auto proto = recv.receive(s0, recvMsg, prng, socket);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  vector<block> mask_msg_0(numOTs);
  vector<block> mask_msg_1(numOTs);
  coproto::sync_wait(socket.recv(mask_msg_0));
  coproto::sync_wait(socket.recv(mask_msg_1));

  for (u64 i = 0; i < numOTs; i++) {
    recvMsg[i] =
        (s0[i]) ? (recvMsg[i] ^ mask_msg_1[i]) : (recvMsg[i] ^ mask_msg_0[i]);
  }

  return recvMsg;
}

void PIS_sender_KKRT_batch(vector<array<block, 2>> &pis_msg,
                           coproto::Socket &socket) {
  const u64 numOTs = pis_msg.size();
  PRNG prng(oc::sysRandomSeed());

  // baseOT recv
  osuCrypto::DefaultBaseOT baseOTs;
  vector<block> baseRecv(128);
  BitVector baseChoice(128);
  baseChoice.randomize(prng);

  auto p = baseOTs.receive(baseChoice, baseRecv, prng, socket);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp sender
  IknpOtExtSender sender;
  sender.setBaseOts(baseRecv, baseChoice);
  vector<array<block, 2>> sendMsg(numOTs);
  vector<block> half_sendMsg_0(numOTs);
  vector<block> half_sendMsg_1(numOTs);

  auto proto = sender.send(sendMsg, prng, socket);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  // random OT -> OT
  for (u64 i = 0; i < numOTs; i++) {
    half_sendMsg_0[i] = pis_msg[i][0] ^ sendMsg[i][0];
    half_sendMsg_1[i] = pis_msg[i][1] ^ sendMsg[i][1];
  }
  coproto::sync_wait(socket.send(half_sendMsg_0));
  coproto::sync_wait(socket.send(half_sendMsg_1));
}

// suppose eles_size is 2^⌈log 𝜇⌉− 1
// compute the split index of vector, reuse
vector<vector<u64>> compute_split_index(const u64 eles_size) {
  u64 vector_num = log2(eles_size);

  vector<vector<u64>> res(vector_num);

  vector<u64> mask(vector_num);
  for (u64 i = 0; i < vector_num; i++) {
    mask[i] = 1 << i;
  }

  for (u64 i = 0; i < eles_size; i++) {
    // check whether the k-th bit of index i in binary representation is 1
    for (u64 j = 0; j < vector_num; j++) {
      if ((i & mask[j]) != 0) {
        res[j].push_back(i);
      }
    }
  }

  return res;
}

// suppose eles_size is 2^⌈log 𝜇⌉− 1
// compute the split index of vector, reuse
vector<vector<u64>> split_vertor(vector<u64> &eles,
                                 const vector<vector<u64>> &eles_index) {
  vector<vector<u64>> res(eles_index.size());
  // spdlog::debug("eles.size {}; eles_index.size {}; eles_index[0].size {}",
  //               eles.size(), eles_index.size(), eles_index[0].size());

  for (u64 i = 0; i < eles_index.size(); i++) {
    for (u64 j = 0; j < eles_index[0].size(); j++) {
      res[i].push_back(eles[eles_index[i][j]]);
    }
  }

  return res;
}