#include "pis_new/batch_peqt.h"
#include "pis_new/equal.h"
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
coproto::task<BitVector> Batch_PEQT_recv(oc::span<block> eles,
                                         coproto::Socket &socket) {
  u64 bit_length = 128;

  BitVector input_bits;
  input_bits.append(reinterpret_cast<u8 *>(eles.data()),
                    eles.size() * bit_length);

  u64 num_triples = eles.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes0;

  co_await triples.gen0(socket);
  co_await eq0(socket, bit_length, triples, input_bits, eqRes0);

  co_return eqRes0;
}

coproto::task<BitVector> Batch_PEQT_send(oc::span<block> datas,
                                         coproto::Socket &socket) {
  u64 bit_length = 128;

  BitVector input_bits;

  input_bits.append(reinterpret_cast<u8 *>(datas.data()),
                    datas.size() * bit_length);

  input_bits = ~input_bits;

  u64 num_triples = datas.size() * bit_length;

  Triples triples(num_triples);
  BitVector eqRes1;

  co_await triples.gen1(socket);
  co_await eq1(socket, bit_length, triples, input_bits, eqRes1);

  co_return eqRes1;
}