#pragma once

#include "cmp_fmap/Defines.h"
#include "cmp_fmap/oprfso.h"
#include "opprf/Opprf.h"
#include "secureJoin/secure-join/Prf/AltModPrfProto.h"
#include "secureJoin/secure-join/Prf/mod3.h"
#include <libOTe/Tools/CoeffCtx.h>
#include <libOTe/Vole/Silent/SilentVoleReceiver.h>
#include <libOTe/Vole/Silent/SilentVoleSender.h>

using namespace oc;
using namespace secJoin;
using namespace volePSI;

namespace CmpFuzzyPSI {

class uFmapSender {
public:
  u64 mSenderSize;
  u64 mRecverSize;
  u64 mDim;
  u64 mDelta;
  u64 mLorH;
  PRNG mPrng;
  AltModPrf::KeyType prfKey;
  block mVoleDelta;
  OprfsoSender mOprfsoSender_0;
  OprfsoReceiver mOprfsoReceiver_1;
  volePSI::RsOpprfReceiver mBopprfReceiver;
  volePSI::RsOpprfSender mBopprfSender;
  Proto setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH,
              PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto fuzzyMap(span<block> inputs, span<block> Identifiers,
                 span<block> oringins, PRNG &prng, Socket &chl,
                 u64 mNumThreads = 1);
};

class uFmapReceiver {
public:
  u64 mSenderSize;
  u64 mRecverSize;
  u64 mDim;
  u64 mDelta;
  u64 mLorH;
  PRNG mPrng;
  AltModPrf::KeyType prfKey;
  block mVoleDelta;
  OprfsoSender mOprfsoSender_1;
  OprfsoReceiver mOprfsoReceiver_0;
  volePSI::RsOpprfSender mBopprfSender;
  volePSI::RsOpprfReceiver mBopprfReceiver;
  Proto setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH,
              PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto fuzzyMap(span<block> inputs, span<block> Identifiers, PRNG &prng,
                 Socket &chl, u64 mNumThreads = 1);
};

oc::block computeBlock2(const oc::block &input, u64 mDelta);
} // namespace CmpFuzzyPSI
