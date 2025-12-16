#include "fpsi_recv.h"
#include "opprf/Opprf.h"
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
#include <unordered_set>
#include <utility>
#include <vector>

void FPSIRecv::DFmap_fig8_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = PrefixParamTable::getSelectedParam(t);

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  // Generate r_x_i
  r_x_i.resize(PTS_NUM * DIM);
  recv_prng.get(r_x_i.data(), PTS_NUM * DIM);
  ID_xr = r_x_i;

  // Generate x_i_s
  vector<pair<u64, u64>> x_i_s(PTS_NUM * DIM);

  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {

      u64 temp0 = (pts[pt_idx][dim_idx] - DELTA) / SIDE_LEN;
      u64 temp1 = pts[pt_idx][dim_idx] / SIDE_LEN;

      x_i_s[pt_idx * DIM + dim_idx] = make_pair(temp0, temp1);
    }
  }

  // Generate dfmap_opprf_keys and dfmap_opprf_values
  auto opprf_num = 4 * PTS_NUM * DIM;
  dfmap_opprf_keys.reserve(opprf_num);
  dfmap_opprf_values.reserve(opprf_num);

  // Generate dfmap_opprf_keys and dfmap_opprf_values
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      block keys[4];
      keys[0] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].first, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].first);
      keys[1] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].first, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].second);
      keys[2] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].second, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].first);
      keys[3] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].second, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].second);

      unordered_set<block> seen_keys;
      for (int i = 0; i < 4; i++) {
        if (seen_keys.insert(keys[i]).second) {
          dfmap_opprf_keys.push_back(keys[i]);
          dfmap_opprf_values.push_back(r_x_i[pt_idx * DIM + dim_idx]);
        }
      }
    }
  }

  padding_blocks(dfmap_opprf_keys, opprf_num);
  padding_blocks(dfmap_opprf_values, opprf_num);

  spdlog::debug("[Recv  ] opprf_0_num: {}, dfmap_opprf_keys: {} ", opprf_num,
                dfmap_opprf_keys.size());
}

void FPSIRecv::DFmap_fig8_online() {
  u64 opprf_size = dfmap_opprf_keys.size();
  u64 opprf_size_other;
  coproto::sync_wait(sockets[0].send(opprf_size));
  coproto::sync_wait(sockets[0].recv(opprf_size_other));

  volePSI::RsOpprfSender sender;

  coproto::sync_wait(sender.send(opprf_size_other, dfmap_opprf_keys,
                                 dfmap_opprf_values, recv_prng, 1, sockets[0]));

  // dfmap_opprf_keys.clear();
  // dfmap_opprf_keys.shrink_to_fit();
  // dfmap_opprf_values.clear();
  // dfmap_opprf_values.shrink_to_fit();
  // dfmap_opprf_1_keys.clear();
  // dfmap_opprf_1_keys.shrink_to_fit();
  // r_x_i.clear();
  // r_x_i.shrink_to_fit();
}

void FPSIRecv::DFmap_fig9_offline() {}
void FPSIRecv::DFmap_fig9_online() {}