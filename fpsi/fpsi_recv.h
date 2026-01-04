#pragma once
#include "config.h"
#include "fpsi_base.h"
#include "opprf/SimpleIndex.h"
#include "utils/params_selects.h"

#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
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

  // parameters during the intermediate process
  u64 SIDE_LEN;  // 2*delta
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta*delta
  PRNG recv_prng;

  // figure 8 dFmap protocol
  PrefixParam DFMAP_PARAM;
  vector<block> dfmap_opprf_keys;
  vector<block> dfmap_opprf_values;
  vector<block> r_x_i;
  vector<block> fig8_ID_xr;

  // figure 9 dFmap protocol
  const ipcl::KeyPair &fmap_recv_key;
  const ipcl::KeyPair &fmap_sender_key;
  vector<u64> IDs;
  vector<u32> fm_mask;
  ipcl::CipherText IDs_ct;
  ipcl::PlainText mask_mul0_pt;
  vector<vector<block>> get_id_encoding;
  vector<u64> fig9_ID_xr;

  BitVector ee;

  // test tmp
  vector<u64> intersection_idxs_tmp;

  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::KeyPair &fmap_recv_key,
           ipcl::KeyPair &fmap_sender_key, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), fmap_recv_key(fmap_recv_key),
        fmap_sender_key(fmap_sender_key), FPSIBase(sockets) {
    // Parameter Initialization
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    recv_prng.SetSeed(oc::sysRandomSeed());
    // recv_prng.SetSeed(block(123, 456));
  };

  void DFmap_fig8_offline();
  void DFmap_fig8_online();

  void DFmap_fig9_offline();
  void DFmap_fig9_offline_fake();
  void DFmap_fig9_online();
  void getID();

  void psi_offline();
  void psi_offline_fake();
  void psi_online();

  void mp_ssFMat_linf(SimpleIndex &st);
  void mp_ssFMat_lp(SimpleIndex &st);
  void ssIFMat_recv(const oc::span<u64> &v_sums);

  void DFmap_fig9_clear() {
    IDs.clear();
    IDs.shrink_to_fit();
    fm_mask.clear();
    fm_mask.shrink_to_fit();
    get_id_encoding.clear();
    get_id_encoding.shrink_to_fit();
    IDs_ct.clear();
    mask_mul0_pt.clear();
  }

  vector<u64> v_sums_;
};