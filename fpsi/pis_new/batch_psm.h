#pragma once

#include "config.h"
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>
#include <vector>

/*
use for batched n vs 1 PEQT
example:
recv_eles[0,batch_size-1]            vs send_datas[0]
recv_eles[batch_size,2*batch_size-1] vs send_datas[1]
.....................................................
recv_eles[.........................] vs send_datas[datas.size()]
*/

coproto::task<BitVector> Batch_PSM_recv(vector<u64> &eles, const u64 batch_size,
                                        coproto::Socket &socket);

coproto::task<BitVector> Batch_PSM_send(vector<u64> &datas, u64 batch_size,
                                        coproto::Socket &socket);
