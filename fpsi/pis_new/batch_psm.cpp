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

#include "pis_new/batch_psm.h"
#include "pis_new/equal.h"
#include "pis_new/triple.h"

coproto::task<BitVector> Batch_PSM_recv(vector<u64> &eles, const u64 batch_size,
                                        coproto::Socket &socket) {
  u64 bit_length = 64;
  auto input_bits = toBitVector(eles, bit_length);
  u64 batch_num = eles.size() / batch_size;
  u64 num_triples = eles.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes0;

  co_await triples.gen0(socket);
  co_await eq0(socket, bit_length, triples, input_bits, eqRes0);

  BitVector s0;
  s0.resize(batch_num, 0);
  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      s0[i] = s0[i] ^ eqRes0[i * batch_size + j];
    }
  }

  co_return s0;
}

coproto::task<BitVector> Batch_PSM_send(vector<u64> &datas, u64 batch_size,
                                        coproto::Socket &socket) {
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

  co_await triples.gen1(socket);
  co_await eq1(socket, bit_length, triples, input_bits, eqRes1);

  BitVector t0;
  t0.resize(batch_num, 0);

  for (u64 i = 0; i < batch_num; i++) {
    for (u64 j = 0; j < batch_size; j++) {
      t0[i] = t0[i] ^ eqRes1[i * batch_size + j];
    }
  }
  co_return t0;
}
