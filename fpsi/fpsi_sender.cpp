#include "fpsi_sender.h"
#include "opprf/Opprf.h"
#include "utils/params_selects.h"
#include "utils/set_dec.h"

#include <cmath>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>
#include <vector>

void FPSISender::DFmap_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = DFmapParamTable::getSelectedParam(t);

  //   get r_(x,i)
  t_y_i.resize(PTS_NUM, vector<block>(DIM));

  for (u64 i = 0; i < PTS_NUM; i++) {
    sender_prng.get(t_y_i[i].data(), DIM);
  }

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  vector<vector<vector<string>>> prefixs(PTS_NUM, vector<vector<string>>(DIM));
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      prefixs[pt_idx][dim_idx] =
          set_prefix(pts[pt_idx][dim_idx], DFMAP_PARAM.first);
    }
  }

  auto opprf_num =
      DFMAP_PARAM.first.size() * DFMAP_PARAM.first.size() * PTS_NUM * DIM;
  dfmap_opprf_0_keys.reserve(opprf_num);
  dfmap_opprf_1_vals.reserve(opprf_num);

  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      for (auto x : prefixs[pt_idx][φ]) {
        for (auto y : prefixs[pt_idx][dim_idx]) {
          auto temp = get_value_fmap_opprf(dim_idx, y, φ, x);
          dfmap_opprf_0_keys.push_back(temp);
          dfmap_opprf_1_vals.push_back(t_y_i[pt_idx][dim_idx]);
        }
      }
    }
  }
  spdlog::debug("[Sender] opprf_num: {}, dfmap_opprf_0_keys size: {}",
                opprf_num, dfmap_opprf_0_keys.size());
}

void FPSISender::DFmap_offline_fake() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = DFmapParamTable::getSelectedParam(t);

  //   get r_(x,i)
  t_y_i.resize(PTS_NUM, vector<block>(DIM));

  for (u64 i = 0; i < PTS_NUM; i++) {
    sender_prng.get(t_y_i[i].data(), DIM);
  }

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  auto opprf_num =
      DFMAP_PARAM.first.size() * DFMAP_PARAM.first.size() * PTS_NUM * DIM;
  dfmap_opprf_0_keys.reserve(opprf_num);
  dfmap_opprf_1_vals.reserve(opprf_num);

  padding_blocks(dfmap_opprf_0_keys, opprf_num);
  padding_blocks(dfmap_opprf_1_vals, opprf_num);
}

void FPSISender::DFmap_online() {

  u64 dfmap_opprf_0_other_num;
  coproto::sync_wait(sockets[0].send(dfmap_opprf_0_keys.size()));
  coproto::sync_wait(sockets[0].recv(dfmap_opprf_0_other_num));

  volePSI::RsOpprfReceiver recv;
  volePSI::RsOpprfSender sender;

  vector<block> dfmap_opprf_0_values(dfmap_opprf_0_keys.size());

  coproto::sync_wait(recv.receive(dfmap_opprf_0_other_num, dfmap_opprf_0_keys,
                                  dfmap_opprf_0_values, sender_prng, 1,
                                  sockets[0]));

  u64 dfmap_opprf_1_other_num;
  coproto::sync_wait(sockets[0].recv(dfmap_opprf_1_other_num));
  coproto::sync_wait(sockets[0].send(dfmap_opprf_0_values.size()));

  coproto::sync_wait(sender.send(dfmap_opprf_1_other_num, dfmap_opprf_0_values,
                                 dfmap_opprf_1_vals, sender_prng, 1,
                                 sockets[0]));

  ID_ys = t_y_i;

  // dfmap_opprf_0_keys.clear();
  // dfmap_opprf_0_keys.shrink_to_fit();
  // dfmap_opprf_1_vals.clear();
  // dfmap_opprf_1_vals.shrink_to_fit();
  // t_y_i.clear();
  // t_y_i.shrink_to_fit();
}

void FPSISender::simple_hash_fake() {}