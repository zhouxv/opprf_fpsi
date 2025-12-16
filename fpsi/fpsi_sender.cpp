#include "fpsi_sender.h"
#include "config.h"
#include "opprf/Opprf.h"
#include "opprf/SimpleIndex.h"
#include "pis_new/batch_psm.h"
#include "utils/params_selects.h"
#include "utils/set_dec.h"
#include "utils/util.h"

#include <cmath>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>
#include <vector>

void FPSISender::DFmap_fig8_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = PrefixParamTable::getSelectedParam(t);

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  // Compute block_4delta
  vector<u64> block_4delta(PTS_NUM * DIM);
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      block_4delta[pt_idx * DIM + dim_idx] =
          (pts[pt_idx][dim_idx] - DELTA) / SIDE_LEN;
    }
  }

  // Compute t_y_j
  t_y_j.resize(PTS_NUM * DIM);
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      t_y_j[pt_idx * DIM + dim_idx] =
          get_fmap_opprf_key(dim_idx, block_4delta[pt_idx * DIM + dim_idx], φ,
                             block_4delta[pt_idx * DIM + φ]);
    }
  }
}

void FPSISender::DFmap_fig8_online() {
  u64 opprf_size_other;
  u64 opprf_size = t_y_j.size();
  coproto::sync_wait(sockets[0].recv(opprf_size_other));
  coproto::sync_wait(sockets[0].send(opprf_size));

  volePSI::RsOpprfReceiver recv;
  vector<block> opprf_values(opprf_size);

  coproto::sync_wait(recv.receive(opprf_size_other, t_y_j, opprf_values,
                                  sender_prng, 1, sockets[0]));

  ID_ys.resize(PTS_NUM, ZeroBlock);
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      ID_ys[pt_idx] = ID_ys[pt_idx] ^ opprf_values[pt_idx * DIM + dim_idx];
    }
  }

  // dfmap_opprf_0_keys.clear();
  // dfmap_opprf_0_keys.shrink_to_fit();
  // dfmap_opprf_1_vals.clear();
  // dfmap_opprf_1_vals.shrink_to_fit();
  // t_y_i.clear();
  // t_y_i.shrink_to_fit();
}

void FPSISender::DFmap_fig9_offline() {}
void FPSISender::DFmap_fig9_online() {}