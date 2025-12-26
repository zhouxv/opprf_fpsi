#pragma once
#include "config.h"

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
                                         coproto::Socket &socket);

coproto::task<BitVector> Batch_PEQT_send(oc::span<block> datas,
                                         coproto::Socket &socket);