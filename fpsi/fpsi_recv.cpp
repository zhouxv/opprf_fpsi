#include "fpsi_recv.h"
#include "opprf/Opprf.h"
#include "utils/set_dec.h"
#include "utils/util.h"

#include <cryptoTools/Common/BitVector.h>
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
  r_x_i.resize(PTS_NUM, vector<block>(DIM));

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
          dfmap_opprf_0_values.push_back(r_x_i[pt_idx][dim_idx]);
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
      dfmap_opprf_1_keys.push_back(r_x_i[i][j]);
    }
  }
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

  ID_xs.resize(PTS_NUM, vector<block>(DIM));

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      ID_xs[i][j] = dfmap_opprf_1_values[i * DIM + j];
    }
  }

  // dfmap_opprf_0_keys.clear();
  // dfmap_opprf_0_keys.shrink_to_fit();
  // dfmap_opprf_0_values.clear();
  // dfmap_opprf_0_values.shrink_to_fit();
  // dfmap_opprf_1_keys.clear();
  // dfmap_opprf_1_keys.shrink_to_fit();
  // r_x_i.clear();
  // r_x_i.shrink_to_fit();
}
