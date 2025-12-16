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

  // dFmap protocol
  PrefixParam DFMAP_PARAM;
  vector<block> t_y_j;
  vector<block> ID_ys;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
      socket.mImpl->mBytesReceived = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), FPSIBase(sockets) {
    // Parameter Initialization
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    sender_prng.SetSeed(oc::sysRandomSeed());
  };

  void DFmap_fig8_offline();
  void DFmap_fig8_online();

  void DFmap_fig9_offline();
  void DFmap_fig9_online();
};
