#pragma once
#include "config.h"
#include "fpsi_base.h"
#include "utils/params_selects.h"
#include "utils/util.h"

#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>
#include <vector>

class FPSIRecv : public FPSIBase {
public:
  // Some important parameters of the protocol
  const u64 DIM;        // dimension
  const u64 DELTA;      // radius
  const u64 PTS_NUM;    // number of point set
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // number of threads

  // References to some core objects
  vector<pt> &pts; // point set
  const ipcl::PublicKey pk;
  const ipcl::PrivateKey sk;

  // parameters during the intermediate process
  u64 SIDE_LEN;  // 2*delta
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta*delta
  PRNG recv_prng;

  // dFmap protocol
  PrefixParam DFMAP_PARAM;
  vector<block> dfmap_opprf_keys;
  vector<block> dfmap_opprf_values;
  vector<block> r_x_i;
  vector<block> ID_xr;

  u64 psi_ca_result = 0;

  void clear() {
    psi_ca_result = 0;
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
      socket.mImpl->mBytesReceived = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  // Pre-computed datas

  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::PublicKey &pk, ipcl::PrivateKey &sk,
           vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), FPSIBase(sockets) {
    // Parameter Initialization
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    recv_prng.SetSeed(oc::sysRandomSeed());
  };

  void DFmap_fig8_offline();
  void DFmap_fig8_online();

  void DFmap_fig9_offline();
  void DFmap_fig9_online();
};