#pragma once
#include "config.h"

#include "pis_new/triple.h"
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>

/*
use for batched 1 vs 1 PEQT
example:
eles[0] vs datas[0]
eles[1] vs datas[2]
...................
eles[n] vs datas[n]
*/
template <typename T>
coproto::task<BitVector> Batch_PEQT_recv(oc::span<T> &eles,
                                         coproto::Socket &socket) {
  u64 bit_length = sizeof(T) * 8;
  auto input_bits = toBitVector(eles, bit_length);
  u64 num_triples = eles.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes0;

  co_await triples.gen0(socket);
  co_await eq0(socket, bit_length, triples, input_bits, eqRes0);

  co_return eqRes0;
}

template <typename T>
coproto::task<BitVector> Batch_PEQT_send(oc::span<T> &datas,
                                         coproto::Socket &socket) {
  u64 bit_length = sizeof(T) * 8;
  auto input_bits = ~toBitVector(datas, bit_length);

  u64 num_triples = datas.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes1;

  co_await triples.gen1(socket);
  co_await eq1(socket, bit_length, triples, input_bits, eqRes1);

  co_return eqRes1;
}