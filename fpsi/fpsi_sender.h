#include "config.h"
#include "fpsi_base.h"
#include "utils/params_selects.h"
#include "utils/util.h"

#include <coproto/Socket/Socket.h>
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

  // figure 8 dFmap protocol
  PrefixParam DFMAP_PARAM;
  vector<block> t_y_j;
  vector<block> fig8_ID_ys;

  // figure 9 dFmap protocol
  const ipcl::KeyPair &fmap_recv_key;
  const ipcl::KeyPair &fmap_sender_key;
  vector<u64> IDs;
  vector<u32> fm_mask;
  ipcl::CipherText IDs_ct;
  ipcl::PlainText mask_mul0_pt;
  vector<vector<block>> get_id_encoding;
  vector<u64> fig9_ID_ys;

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

  void DFmap_fig8_offline();
  void DFmap_fig8_online();

  void getID();
  void DFmap_fig9_offline();
  void DFmap_fig9_offline_fake();
  void DFmap_fig9_online();
};
