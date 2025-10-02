#pragma once

#include "config.h"
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>
#include <vector>

coproto::task<BitVector> Batch_PSM_recv(vector<u64> &eles, const u64 batch_size,
                                        coproto::Socket &socket);

coproto::task<BitVector> Batch_PSM_send(vector<u64> &datas, u64 batch_size,
                                        coproto::Socket &socket);
