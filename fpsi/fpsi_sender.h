#include "cmp_fmap/fmap.h"
#include "config.h"
#include "fpsi_base.h"
#include "utils/params_selects.h"

#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/pri_key.hpp>
#include <vector>

class FPSISender : public FPSIBase {
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
  PRNG sender_prng;
  const ipcl::KeyPair &fmap_recv_key;
  const ipcl::KeyPair &fmap_sender_key;

  // F_mat results
  BitVector ee;

  // vole results
  AlignedUnVector<u32> d_vole;
  u32 b_delta;

  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::KeyPair &fmap_recv_key,
             ipcl::KeyPair &fmap_sender_key, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), fmap_recv_key(fmap_recv_key),
        fmap_sender_key(fmap_sender_key), FPSIBase(sockets) {
    // Parameter Initialization
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    sender_prng.SetSeed(oc::sysRandomSeed());
    // sender_prng.SetSeed(block(123, 123));
  };

  // spatial hash PSI
  vector<block> sh_ID_ys;
  template <CuckooTypes Mode> void mp_ssFMat_linf_sh(CuckooIndex<Mode> &ct);
  template <CuckooTypes Mode> void mp_ssFMat_lp_sh(CuckooIndex<Mode> &ct);
  void psi_offline_sh();
  void psi_online_sh();

  // cmp fmap psi
  vector<block> cmp_ID;
  vector<block> sender_data;
  CmpFuzzyPSI::FmapSender cmp_fmap_sender;
  void psi_offline_cmp();
  void psi_online_cmp();
  void cmp_fmap();
  void cmp_fmap_offline();
  void cmp_fmap_online();
  template <CuckooTypes Mode> void mp_ssFMat_linf(CuckooIndex<Mode> &ct);
  template <CuckooTypes Mode> void mp_ssFMat_lp(CuckooIndex<Mode> &ct);
  void ssIFMat_send(const oc::span<u64> &u_sums);

  // Figure 9 dFmap
  // vector<u64> fig9_ID_ys;
  // vector<u64> IDs;
  // vector<u32> fm_mask;
  // ipcl::CipherText IDs_ct;
  // ipcl::PlainText mask_mul0_pt;
  // vector<vector<block>> get_id_encoding;

  // void getID();
  // void DFmap_fig9_offline();
  // void DFmap_fig9_offline_fake();
  // void DFmap_fig9_online();

  // Figure 9 PSI
  // void psi_offline();
  // void psi_offline_fake();
  // void psi_online();

  // Figure 8 dFmap
  // vector<block> t_y_j;
  // vector<block> fig8_ID_ys;

  // void DFmap_fig8_offline();
  // void DFmap_fig8_online();

  // Figure 8 PSI
  // void psi_offline_fig8();
  // void psi_online_fig8();
  // template <CuckooTypes Mode> void mp_ssFMat_linf_fig8(CuckooIndex<Mode>
  // &ct); template <CuckooTypes Mode> void mp_ssFMat_lp_fig8(CuckooIndex<Mode>
  // &ct);
};
