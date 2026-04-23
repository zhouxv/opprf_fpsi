#pragma once
#include "config.h"
#include "fpsi_base.h"
#include "opprf/Defines.h"
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
  const ipcl::KeyPair &fmap_recv_key;
  const ipcl::KeyPair &fmap_sender_key;

  // F_mat results
  BitVector ee;

  // vole results
  AlignedUnVector<u32> a_vole, c_vole;

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

  // figure 9 dFmap protocol
  vector<u64> IDs;
  vector<u32> fm_mask;
  ipcl::CipherText IDs_ct;
  ipcl::PlainText mask_mul0_pt;
  vector<vector<block>> get_id_encoding;
  vector<u64> fig9_ID_xr;

  void getID();
  void DFmap_fig9_offline();
  void DFmap_fig9_offline_fake();
  void DFmap_fig9_online();

  // Figure 9 PSI
  void mp_ssFMat_linf(SimpleIndex &st);
  void mp_ssFMat_lp(SimpleIndex &st);
  void ssIFMat_recv(const oc::span<u64> &v_sums);
  void psi_offline();
  void psi_offline_fake();
  void psi_online();

  // Figure 8 dFmap
  vector<block> dfmap_opprf_keys;
  vector<block> dfmap_opprf_values;
  vector<block> r_x_i;
  vector<block> fig8_ID_xr;

  void DFmap_fig8_offline();
  void DFmap_fig8_online();

  // Figure 8 PSI
  void mp_ssFMat_linf_fig8(SimpleIndex &st);
  void mp_ssFMat_lp_fig8(SimpleIndex &st);
  void psi_offline_fig8();
  void psi_online_fig8();

  // spatial hash PSI
  vector<block> sh_ID_xr;
  void mp_ssFMat_linf_sh(SimpleIndex &st);
  void mp_ssFMat_lp_sh(SimpleIndex &st);
  void psi_offline_sh();
  void psi_online_sh();

  // cmp fmap psi
  void cmp_fmap();
  void psi_offline_cmp();
  void psi_online_cmp();
};