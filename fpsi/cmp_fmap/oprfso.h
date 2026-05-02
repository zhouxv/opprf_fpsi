#pragma once

#include "Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "secureJoin/secure-join/AggTree/PerfectShuffle.h"
#include "secureJoin/secure-join/Prf/AltModPrfProto.h"
#include "secureJoin/secure-join/Prf/mod3.h"

using namespace oc;
using namespace secJoin;

namespace CmpFuzzyPSI {

class OprfsoSender : public oc::TimerAdapter {
public:
  AltModWPrfSender mAltModWPrfSender;
  CorGenerator ole;

  Proto setUp(u64 receiverSize, PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto oprfSo(span<oc::block> oprfShare, PRNG &prng, Socket &chl,
               u64 mNumThreads = 1);
};

class OprfsoReceiver : public oc::TimerAdapter {
public:
  AltModWPrfReceiver mAltModWPrfReceiver;
  CorGenerator ole;

  Proto setUp(u64 receiverSize, PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto oprfSo(span<oc::block> data, span<oc::block> oprfShare, PRNG &prng,
               Socket &chl, u64 mNumThreads = 1);
};

} // namespace CmpFuzzyPSI