#include "fpsi_recv.h"
#include "config.h"
#include "opprf/Opprf.h"
#include "pis_new/batch_psm.h"
#include "utils/set_dec.h"
#include "utils/util.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

void FPSIRecv::DFmap_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = DFmapParamTable::getSelectedParam(t);

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  vector<vector<vector<string>>> prefixs(PTS_NUM, vector<vector<string>>(DIM));
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      prefixs[pt_idx][dim_idx] =
          set_dec(pts[pt_idx][dim_idx] - DELTA, pts[pt_idx][dim_idx] + DELTA,
                  DFMAP_PARAM.first);
    }
  }

  //   get r_(x,i)
  r_x_i.resize(PTS_NUM * DIM);

  for (u64 i = 0; i < PTS_NUM; i++) {
    recv_prng.get(r_x_i[i].data(), DIM);
  }

  auto opprf_0_num = DFMAP_PARAM.second * DFMAP_PARAM.second * PTS_NUM * DIM;
  dfmap_opprf_0_keys.reserve(opprf_0_num);
  dfmap_opprf_0_values.reserve(opprf_0_num);

  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      for (auto x : prefixs[pt_idx][φ]) {
        for (auto y : prefixs[pt_idx][dim_idx]) {
          auto temp = get_value_fmap_opprf(φ, x, dim_idx, y);
          dfmap_opprf_0_keys.push_back(temp);
          dfmap_opprf_0_values.push_back(r_x_i[pt_idx * DIM + dim_idx]);
        }
      }
    }
  }

  spdlog::debug("[Recv  ] opprf_0_num: {}, dfmap_opprf_0_keys: {} ",
                opprf_0_num, dfmap_opprf_0_keys.size());

  padding_blocks(dfmap_opprf_0_keys, opprf_0_num);
  padding_blocks(dfmap_opprf_0_values, opprf_0_num);

  dfmap_opprf_1_keys.reserve(PTS_NUM * DIM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      dfmap_opprf_1_keys.push_back(r_x_i[i * DIM + j]);
    }
  }
}

void FPSIRecv::DFmap_offline_fake() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = DFmapParamTable::getSelectedParam(t);

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  //   get r_(x,i)
  r_x_i.resize(PTS_NUM * DIM);
  recv_prng.get(r_x_i.data(), PTS_NUM * DIM);

  auto opprf_0_num = DFMAP_PARAM.second * DFMAP_PARAM.second * PTS_NUM * DIM;
  dfmap_opprf_0_keys.reserve(opprf_0_num);
  dfmap_opprf_0_values.reserve(opprf_0_num);

  padding_blocks(dfmap_opprf_0_keys, opprf_0_num);
  padding_blocks(dfmap_opprf_0_values, opprf_0_num);

  dfmap_opprf_1_keys.reserve(PTS_NUM * DIM);
  padding_blocks(dfmap_opprf_1_keys, PTS_NUM * DIM);
}

void FPSIRecv::DFmap_online() {
  u64 dfmap_opprf_0_other_num;
  coproto::sync_wait(sockets[0].recv(dfmap_opprf_0_other_num));
  coproto::sync_wait(sockets[0].send(dfmap_opprf_0_keys.size()));

  volePSI::RsOpprfSender sender;
  volePSI::RsOpprfReceiver recv;

  coproto::sync_wait(sender.send(dfmap_opprf_0_other_num, dfmap_opprf_0_keys,
                                 dfmap_opprf_0_values, recv_prng, 1,
                                 sockets[0]));

  u64 dfmap_opprf_1_other_num;
  coproto::sync_wait(sockets[0].send(PTS_NUM * DIM));
  coproto::sync_wait(sockets[0].recv(dfmap_opprf_1_other_num));

  vector<block> dfmap_opprf_1_values(PTS_NUM * DIM);
  coproto::sync_wait(recv.receive(dfmap_opprf_1_other_num, dfmap_opprf_1_keys,
                                  dfmap_opprf_1_values, recv_prng, 1,
                                  sockets[0]));

  ID_xs = dfmap_opprf_1_values;

  // dfmap_opprf_0_keys.clear();
  // dfmap_opprf_0_keys.shrink_to_fit();
  // dfmap_opprf_0_values.clear();
  // dfmap_opprf_0_values.shrink_to_fit();
  // dfmap_opprf_1_keys.clear();
  // dfmap_opprf_1_keys.shrink_to_fit();
  // r_x_i.clear();
  // r_x_i.shrink_to_fit();
}

void FPSIRecv::cuckoo_hash_fake() {
  // idx：表示存储在该桶中的项目的索引（index）。它通常是与实际数据项关联的索引值。可以通过
  //     load() 方法提取。 idx 是 mVal 的低 56 位（mVal 的高 8
  //     位用于存储hashIdx），代表
  //     当前桶存储的数据项的索引。
  //
  // hashIdx：表示与该桶相关的哈希函数的索引。也就是该桶是由哪个哈希函数生成的。在
  //          Cuckoo哈希表中，一项数据可能通过多个哈希函数计算出多个桶的位置，而
  //          hashIdx 表示该桶是由哪个哈希函数生成的。 hashIdx 是mVal 的高 8
  //          位， 指示该项使用哪个哈希函数生成。

  ID_xs.resize(PTS_NUM * DIM);
  recv_prng.get(ID_xs.data(), PTS_NUM * DIM);

  CuckooIndex<NotThreadSafe> cuckoo;
  cuckoo.init(PTS_NUM * DIM, 40, 0, 3);

  cuckoo.insert(ID_xs, CUCKOO_SEED);

  auto m = cuckoo.mBins.size();

  spdlog::debug("[Recv] bins_size: {}", m);
}

void FPSIRecv::ssFmatLinf() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = DFmapParamTable::getSelectedParam(t);

  auto params =
      CuckooIndex<NotThreadSafe>::selectParams(PTS_NUM * DIM, 40, 0, 3);
  auto bins_size = params.numBins();

  volePSI::SimpleIndex simple_index;
  simple_index.init(bins_size, PTS_NUM * DIM, 40, 3);
  auto max_b = simple_index.mMaxBinSize;

  auto count = max_b * bins_size * DIM * DFMAP_PARAM.second;

  vector<block> list(count);
  vector<block> vals(count);
  recv_prng.get(list.data(), count);

  volePSI::RsOpprfSender sender;

  u64 opprf_0_other_num;
  coproto::sync_wait(sockets[0].send(count));
  coproto::sync_wait(sockets[0].recv(opprf_0_other_num));
  spdlog::debug("[Recv] opprf_0:{} {} {} {}", count, opprf_0_other_num,
                list.size(), vals.size());

  coproto::sync_wait(
      sender.send(opprf_0_other_num, list, vals, recv_prng, 1, sockets[0]));

  volePSI::RsOpprfReceiver recv;

  u64 opprf_1_other_num;
  coproto::sync_wait(sockets[0].send(vals.size()));
  coproto::sync_wait(sockets[0].recv(opprf_1_other_num));

  vector<block> b(vals.size());

  spdlog::debug("[Recv] opprf_1: {} {} {} {}", vals.size(), opprf_1_other_num,
                vals.size(), b.size());

  recv_prng.get(vals.data(), vals.size());
  recv_prng.get(b.data(), b.size());

  coproto::sync_wait(
      recv.receive(opprf_1_other_num, vals, b, recv_prng, 1, sockets[0]));

  vector<u64> plain_nums(b.size());
  recv_prng.get(plain_nums.data(), b.size());

  auto r = Batch_PSM_recv(plain_nums, 1, sockets[0]);
  auto rr = sync_wait(r);

  spdlog::debug("[Recv] {} {}", b.size(), bins_size);
  spdlog::debug("[Recv] Batch_PSM_recv");

  // vector<u64> plain_nums2(bins_size);
  // recv_prng.get(plain_nums2.data(), bins_size);

  // auto r2 = Batch_PSM_recv(plain_nums2, 1, sockets[0]);
  // auto rr2 = sync_wait(r2);
  // spdlog::debug("[Recv] Batch_PSM_recv");
}

void FPSIRecv::ssFmatLp() {
  auto params =
      CuckooIndex<NotThreadSafe>::selectParams(PTS_NUM * DIM, 40, 0, 3);
  auto bins_size = params.numBins();

  volePSI::SimpleIndex simple_index;
  simple_index.init(bins_size, PTS_NUM * DIM, 40, 3);
  auto max_b = simple_index.mMaxBinSize;
}
