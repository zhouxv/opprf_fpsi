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

BitVector toBitVector(std::span<u64> data, u64 length);