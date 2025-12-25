#pragma once
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <macoro/task.h>

#include "config.h"
#include "pis_new/triple.h"

coproto::task<> eq0(coproto::Socket &chl, u64 length, Triples &triples,
                    BitVector &in0, BitVector &res0);
coproto::task<> eq1(coproto::Socket &chl, u64 length, Triples &triples,
                    BitVector &in1, BitVector &res1);

template <typename T> BitVector toBitVector(oc::span<T> data, u64 length) {
  BitVector bv(data.size() * length);
  for (u64 i = 0; i < data.size(); i++) {
    for (u64 j = 0; j < length; j++) {
      bv[i * length + j] = (data[i] >> j) & 1;
    }
  }
  return bv;
}