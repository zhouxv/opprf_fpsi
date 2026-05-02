#pragma once

#include "Defines.h"
#include "oprfso.h"
#include "secureJoin/secure-join/AggTree/PerfectShuffle.h"
#include "secureJoin/secure-join/Prf/AltModPrfProto.h"
#include "secureJoin/secure-join/Prf/mod3.h"
#include <SecureJoinOTe/Tools/CoeffCtx.h>
#include <SecureJoinOTe/Vole/Silent/SilentVoleReceiver.h>
#include <SecureJoinOTe/Vole/Silent/SilentVoleSender.h>

#include "opprf/Paxos.h"

using namespace SecureJoinOTe;
using namespace secJoin;
using namespace volePSI;

namespace CmpFuzzyPSI {

class FmapSender {
public:
  u64 mSenderSize;
  u64 mRecverSize;
  u64 mDim;
  u64 mDelta;
  u64 mLorH;
  PRNG mPrng;
  u64 orgSize;
  AltModPrf::KeyType prfKey;

  // random VOLE instances, sScalar * rMask = rMask_share[r] + rMask_share[s],
  // GF(128) random VOLE instances, rScalar * sMask = sMask_share[r] +
  // sMask_share[s], GF(128)
  block sScalar;
  std::vector<block> sMask;
  std::vector<block> sMask_share;
  std::vector<block> rMask_share;

  Baxos mPaxos;
  Baxos paxos;

  AltModPrf dm_0;
  OprfsoSender mOprfsoSender_0;
  OprfsoReceiver mOprfsoReceiver_1;

  void getID(span<block> inputs, span<block> mIdentifiers,
             span<block> blocksContainInputs, span<block> mAssignments,
             span<block> oringins, PRNG &prng);
  Proto setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH,
              PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto fuzzyMap(span<block> inputs, span<block> Identifiers,
                 span<block> oringins, PRNG &prng, Socket &chl,
                 u64 mNumThreads = 1);
};

class FmapReceiver {
public:
  u64 mSenderSize;
  u64 mRecverSize;
  u64 mDim;
  u64 mDelta;
  u64 mLorH;
  PRNG mPrng;
  u64 orgSize;
  AltModPrf::KeyType prfKey;

  block rScalar;
  std::vector<block> rMask;
  std::vector<block> rMask_share;
  std::vector<block> sMask_share;

  Baxos paxos;
  Baxos mPaxos;

  AltModPrf dm_1;
  OprfsoSender mOprfsoSender_1;
  OprfsoReceiver mOprfsoReceiver_0;

  void getID(span<block> inputs, span<block> mIdentifiers,
             span<block> blocksContainInputs, span<block> mAssignments,
             PRNG &prng);
  Proto setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH,
              PRNG &prng, Socket &chl, u64 mNumThreads = 1);
  Proto fuzzyMap(span<block> inputs, span<block> Identifiers, PRNG &prng,
                 Socket &chl, u64 mNumThreads = 1);
};

oc::block computeBlock(const oc::block &input, u64 mDelta);
oc::block computeCell(const oc::block &input, u64 mDelta);
oc::block leftEndPoint(const oc::block &input, u64 mDelta);
} // namespace CmpFuzzyPSI