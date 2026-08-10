#include "ufmap.h"

#include <unordered_map>

namespace CmpFuzzyPSI {
namespace {

using oc::AlignedUnVector;
using oc::SilentVoleReceiver;
using oc::SilentVoleSender;

struct EncodedSet {
  std::vector<block> ids;
  std::vector<std::vector<block>> keys;
  std::vector<std::vector<block>> values;
};

u64 low64(const block &value) { return value.get<u64>(0); }
u64 high64(const block &value) { return value.get<u64>(1); }
block fromLow64(u64 value) { return block(0, value); }

u64 cell2Delta(const block &input, u64 delta) {
  const auto width = 2 * delta;
  return width ? low64(input) / width : 0;
}

u64 canonicalBlock4Delta(const block &input, u64 delta) {
  const auto value = low64(input);
  const auto width = 2 * delta;
  return width ? (value >= delta ? (value - delta) / width : 0) : 0;
}

block coordinateBlock(u64 coordinate, u64 cell) {
  return block(coordinate, 0) ^ fromLow64(cell);
}

std::array<block, 2> candidateBlocks(const block &input, u64 coordinate,
                                     u64 delta) {
  const auto value = low64(input);
  const auto width = 2 * delta;
  const auto left = width && value >= width ? (value - width) / width : 0;
  return {coordinateBlock(coordinate, cell2Delta(input, delta)),
          coordinateBlock(coordinate, left)};
}

EncodedSet getID(span<block> inputs, u64 size, u64 dim, u64 delta,
                 const AltModPrf::KeyType &key, PRNG &prng) {
  EncodedSet result;
  result.ids.assign(size, ZeroBlock);
  result.keys.resize(dim);
  result.values.resize(dim);

  AltModPrf prf;
  prf.setKey(key);

  for (u64 i = 0; i < dim; ++i) {
    std::unordered_map<block, block> labels;
    for (u64 k = 0; k < size; ++k) {
      const auto label =
          coordinateBlock(i, canonicalBlock4Delta(inputs[k * dim + i], delta));
      auto [it, inserted] = labels.emplace(label, ZeroBlock);
      if (inserted)
        it->second = fromLow64(prng.get<u64>());
      result.ids[k] ^= it->second;
    }

    result.keys[i].reserve(size);
    result.values[i].reserve(size);
    for (const auto &[label, value] : labels) {
      result.keys[i].push_back(label);
      // The high half is zero before masking.  This lets the bOPPRF use the
      // high half of the secret-shared OPRF output as its query key.
      result.values[i].push_back(value ^ prf.eval(label));
    }

    while (result.keys[i].size() < size) {
      auto dummy = prng.get<block>() ^ block(i, 0);
      if (labels.contains(dummy))
        continue;
      labels.emplace(dummy, ZeroBlock);
      result.keys[i].push_back(dummy);
      result.values[i].push_back(prng.get<block>());
    }
  }
  return result;
}

void sendEncoding(const EncodedSet &encoding, u64 size, u64 dim, PRNG &prng,
                  Socket &chl, u64 threads) {
  for (u64 i = 0; i < dim; ++i) {
    auto seed = prng.get<block>();
    Baxos paxos;
    paxos.init(size, 1 << 14, 3, 40, PaxosParam::GF128, seed);
    std::vector<block> table(paxos.size());
    paxos.solve<block>(encoding.keys[i], encoding.values[i], table, &prng,
                       threads);
    macoro::sync_wait(chl.send(std::move(seed)));
    macoro::sync_wait(chl.send(std::move(table)));
  }
}

std::vector<block> receiveAndDecode(span<block> inputs, u64 inputSize,
                                    u64 ownerSize, u64 dim, u64 delta,
                                    Socket &chl, u64 threads) {
  std::vector<block> decoded(2 * inputSize * dim);
  for (u64 i = 0; i < dim; ++i) {
    block seed;
    macoro::sync_wait(chl.recv(seed));
    Baxos paxos;
    paxos.init(ownerSize, 1 << 14, 3, 40, PaxosParam::GF128, seed);
    std::vector<block> table(paxos.size());
    macoro::sync_wait(chl.recv(table));

    std::vector<block> queries(2 * inputSize);
    std::vector<block> values(2 * inputSize);
    for (u64 k = 0; k < inputSize; ++k) {
      const auto candidates = candidateBlocks(inputs[k * dim + i], i, delta);
      queries[2 * k] = candidates[0];
      queries[2 * k + 1] = candidates[1];
    }
    paxos.mAddToDecode = true;
    paxos.decode<block>(queries, values, table, threads);
    for (u64 k = 0; k < inputSize; ++k) {
      decoded[2 * (k * dim + i)] = values[2 * k];
      decoded[2 * (k * dim + i) + 1] = values[2 * k + 1];
    }
  }
  return decoded;
}

std::vector<block> makeCandidates(span<block> inputs, u64 size, u64 dim,
                                  u64 delta) {
  std::vector<block> candidates(2 * size * dim);
  for (u64 k = 0; k < size; ++k) {
    for (u64 i = 0; i < dim; ++i) {
      const auto pair = candidateBlocks(inputs[k * dim + i], i, delta);
      candidates[2 * (k * dim + i)] = pair[0];
      candidates[2 * (k * dim + i) + 1] = pair[1];
    }
  }
  return candidates;
}

std::vector<block> makeAlignment(const std::vector<block> &keyShares) {
  std::vector<block> alignment(keyShares.size() / 2);
  for (u64 q = 0; q < alignment.size(); ++q)
    alignment[q] = keyShares[2 * q] ^ keyShares[2 * q + 1];
  return alignment;
}

void applyAlignment(std::vector<block> &queryShares,
                    const std::vector<block> &alignment) {
  for (u64 q = 0; q < alignment.size(); ++q)
    queryShares[2 * q + 1] ^= alignment[q];
}

std::vector<block> queryKeys(const std::vector<block> &keyShares) {
  std::vector<block> keys(keyShares.size() / 2);
  for (u64 q = 0; q < keys.size(); ++q)
    keys[q] = fromLow64(high64(keyShares[2 * q]));
  return keys;
}

void programBopprf(const std::vector<block> &decoded,
                   const std::vector<block> &queryShares, PRNG &prng,
                   std::vector<block> &programKeys,
                   std::vector<block> &programValues,
                   std::vector<block> &programmerShares) {
  const auto queries = queryShares.size() / 2;
  programKeys.resize(2 * queries);
  programValues.resize(2 * queries);
  programmerShares.resize(queries);
  for (u64 q = 0; q < queries; ++q) {
    programmerShares[q] = fromLow64(prng.get<u64>());
    for (u64 sigma = 0; sigma < 2; ++sigma) {
      const auto rho = decoded[2 * q + sigma] ^ queryShares[2 * q + sigma];
      programKeys[2 * q + sigma] = fromLow64(high64(rho));
      programValues[2 * q + sigma] =
          fromLow64(low64(rho) ^ low64(programmerShares[q]));
    }
  }
}

std::vector<block> recoverReceiverShares(const std::vector<block> &outputs,
                                         const std::vector<block> &keyShares) {
  std::vector<block> shares(outputs.size());
  for (u64 q = 0; q < outputs.size(); ++q)
    shares[q] = fromLow64(low64(outputs[q]) ^ low64(keyShares[2 * q]));
  return shares;
}

block sumPointShares(const std::vector<block> &shares, u64 point, u64 dim) {
  block sum = ZeroBlock;
  for (u64 i = 0; i < dim; ++i)
    sum ^= shares[point * dim + i];
  return sum;
}

} // namespace

oc::block computeBlock2(const oc::block &input, u64 delta) {
  return fromLow64(canonicalBlock4Delta(input, delta));
}

Proto uFmapSender::setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta,
                         u64 LorH, PRNG &prng, Socket &chl, u64 threads) {
  mSenderSize = senderSize;
  mRecverSize = receiverSize;
  mDim = dim;
  mDelta = delta;
  mLorH = LorH;
  // The scalar is sampled once per party.  The remaining setup follows the
  // two OPRF-so directions of Figure \ref{pk UFmap construction}.
  mVoleDelta = prng.get<block>();
  macoro::sync_wait(
      mOprfsoSender_0.setUp(2 * receiverSize * dim, prng, chl, threads));
  prfKey = mOprfsoSender_0.mAltModWPrfSender.getKey();
  macoro::sync_wait(
      mOprfsoReceiver_1.setUp(2 * senderSize * dim, prng, chl, threads));
  co_return;
}

Proto uFmapReceiver::setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta,
                           u64 LorH, PRNG &prng, Socket &chl, u64 threads) {
  mSenderSize = senderSize;
  mRecverSize = receiverSize;
  mDim = dim;
  mDelta = delta;
  mLorH = LorH;
  mVoleDelta = prng.get<block>();
  macoro::sync_wait(
      mOprfsoReceiver_0.setUp(2 * receiverSize * dim, prng, chl, threads));
  macoro::sync_wait(
      mOprfsoSender_1.setUp(2 * senderSize * dim, prng, chl, threads));
  prfKey = mOprfsoSender_1.mAltModWPrfSender.getKey();
  co_return;
}

Proto uFmapSender::fuzzyMap(span<block> inputs, span<block> identifiers,
                            span<block> origins, PRNG &prng, Socket &chl,
                            u64 threads) {
  auto local = getID(inputs, mSenderSize, mDim, mDelta, prfKey, prng);
  for (u64 k = 0; k < mSenderSize; ++k)
    for (u64 i = 0; i < mDim; ++i)
      origins[k * mDim + i] = computeBlock2(inputs[k * mDim + i], mDelta);

  // Direction 1: this party owns the encoded blocks and the other party
  // obtains its mapped identifiers.
  sendEncoding(local, mSenderSize, mDim, prng, chl, threads);
  std::vector<block> keyShares(2 * mRecverSize * mDim);
  macoro::sync_wait(mOprfsoSender_0.oprfSo(keyShares, prng, chl, threads));
  macoro::sync_wait(chl.send(makeAlignment(keyShares)));

  const auto keys = queryKeys(keyShares);
  std::vector<block> bopprfOutput(keys.size());
  macoro::sync_wait(mBopprfReceiver.receive(2 * keys.size(), keys, bopprfOutput,
                                            prng, threads, chl));
  const auto receiverShares = recoverReceiverShares(bopprfOutput, keyShares);

  SilentVoleReceiver<block, block> firstVoleReceiver;
  AlignedUnVector<block> firstA(mRecverSize), firstC(mRecverSize);
  macoro::sync_wait(firstVoleReceiver.silentReceive(firstC, firstA, prng, chl));
  std::vector<block> u(mRecverSize);
  for (u64 k = 0; k < mRecverSize; ++k)
    u[k] = firstC[k] ^ sumPointShares(receiverShares, k, mDim);
  macoro::sync_wait(chl.send(std::move(u)));

  SilentVoleSender<block, block> secondVoleSender;
  AlignedUnVector<block> secondD(mRecverSize);
  macoro::sync_wait(
      secondVoleSender.silentSend(mVoleDelta, secondD, prng, chl));
  std::vector<block> v(mRecverSize), w(mRecverSize);
  macoro::sync_wait(chl.recv(v));
  for (u64 k = 0; k < mRecverSize; ++k)
    w[k] = mVoleDelta.gf128Mul(v[k] ^ firstA[k]) ^ secondD[k];
  macoro::sync_wait(chl.send(std::move(w)));

  // Direction 2: exchange roles so that this party obtains identifiers.
  const auto decoded = receiveAndDecode(inputs, mSenderSize, mRecverSize, mDim,
                                        mDelta, chl, threads);
  auto candidates = makeCandidates(inputs, mSenderSize, mDim, mDelta);
  std::vector<block> queryShares(candidates.size());
  macoro::sync_wait(
      mOprfsoReceiver_1.oprfSo(candidates, queryShares, prng, chl, threads));
  std::vector<block> alignment(queryShares.size() / 2);
  macoro::sync_wait(chl.recv(alignment));
  applyAlignment(queryShares, alignment);

  std::vector<block> programKeys, programValues, programmerShares;
  programBopprf(decoded, queryShares, prng, programKeys, programValues,
                programmerShares);
  macoro::sync_wait(mBopprfSender.send(queryShares.size() / 2, programKeys,
                                       programValues, prng, threads, chl));

  SilentVoleSender<block, block> thirdVoleSender;
  AlignedUnVector<block> thirdD(mSenderSize);
  macoro::sync_wait(thirdVoleSender.silentSend(mVoleDelta, thirdD, prng, chl));
  std::vector<block> thirdU(mSenderSize);
  macoro::sync_wait(chl.recv(thirdU));
  std::vector<block> senderTerms(mSenderSize);
  for (u64 k = 0; k < mSenderSize; ++k)
    senderTerms[k] = mVoleDelta.gf128Mul(
                         thirdU[k] ^ sumPointShares(programmerShares, k, mDim) ^
                         local.ids[k]) ^
                     thirdD[k];

  SilentVoleReceiver<block, block> fourthVoleReceiver;
  AlignedUnVector<block> fourthA(mSenderSize), fourthC(mSenderSize);
  macoro::sync_wait(
      fourthVoleReceiver.silentReceive(fourthC, fourthA, prng, chl));
  std::vector<block> fourthV(mSenderSize), fourthW(mSenderSize);
  for (u64 k = 0; k < mSenderSize; ++k)
    fourthV[k] = fourthC[k] ^ senderTerms[k];
  macoro::sync_wait(chl.send(std::move(fourthV)));
  macoro::sync_wait(chl.recv(fourthW));
  for (u64 k = 0; k < mSenderSize; ++k)
    identifiers[k] = fourthW[k] ^ fourthA[k];
  co_await chl.flush();
}

Proto uFmapReceiver::fuzzyMap(span<block> inputs, span<block> identifiers,
                              PRNG &prng, Socket &chl, u64 threads) {
  auto local = getID(inputs, mRecverSize, mDim, mDelta, prfKey, prng);

  // Direction 1: query the sender's encoded blocks.
  const auto decoded = receiveAndDecode(inputs, mRecverSize, mSenderSize, mDim,
                                        mDelta, chl, threads);
  auto candidates = makeCandidates(inputs, mRecverSize, mDim, mDelta);
  std::vector<block> queryShares(candidates.size());
  macoro::sync_wait(
      mOprfsoReceiver_0.oprfSo(candidates, queryShares, prng, chl, threads));
  std::vector<block> alignment(queryShares.size() / 2);
  macoro::sync_wait(chl.recv(alignment));
  applyAlignment(queryShares, alignment);

  std::vector<block> programKeys, programValues, programmerShares;
  programBopprf(decoded, queryShares, prng, programKeys, programValues,
                programmerShares);
  macoro::sync_wait(mBopprfSender.send(queryShares.size() / 2, programKeys,
                                       programValues, prng, threads, chl));

  SilentVoleSender<block, block> firstVoleSender;
  AlignedUnVector<block> firstD(mRecverSize);
  macoro::sync_wait(firstVoleSender.silentSend(mVoleDelta, firstD, prng, chl));
  std::vector<block> firstU(mRecverSize), senderTerms(mRecverSize);
  macoro::sync_wait(chl.recv(firstU));
  for (u64 k = 0; k < mRecverSize; ++k)
    senderTerms[k] = mVoleDelta.gf128Mul(
                         firstU[k] ^ sumPointShares(programmerShares, k, mDim) ^
                         local.ids[k]) ^
                     firstD[k];

  SilentVoleReceiver<block, block> secondVoleReceiver;
  AlignedUnVector<block> secondA(mRecverSize), secondC(mRecverSize);
  macoro::sync_wait(
      secondVoleReceiver.silentReceive(secondC, secondA, prng, chl));
  std::vector<block> secondV(mRecverSize), secondW(mRecverSize);
  for (u64 k = 0; k < mRecverSize; ++k)
    secondV[k] = secondC[k] ^ senderTerms[k];
  macoro::sync_wait(chl.send(std::move(secondV)));
  macoro::sync_wait(chl.recv(secondW));
  for (u64 k = 0; k < mRecverSize; ++k)
    identifiers[k] = secondW[k] ^ secondA[k];

  // Direction 2: this party now owns the encoded blocks.
  sendEncoding(local, mRecverSize, mDim, prng, chl, threads);
  std::vector<block> keyShares(2 * mSenderSize * mDim);
  macoro::sync_wait(mOprfsoSender_1.oprfSo(keyShares, prng, chl, threads));
  macoro::sync_wait(chl.send(makeAlignment(keyShares)));

  const auto keys = queryKeys(keyShares);
  std::vector<block> bopprfOutput(keys.size());
  macoro::sync_wait(mBopprfReceiver.receive(2 * keys.size(), keys, bopprfOutput,
                                            prng, threads, chl));
  const auto receiverShares = recoverReceiverShares(bopprfOutput, keyShares);

  SilentVoleReceiver<block, block> thirdVoleReceiver;
  AlignedUnVector<block> thirdA(mSenderSize), thirdC(mSenderSize);
  macoro::sync_wait(thirdVoleReceiver.silentReceive(thirdC, thirdA, prng, chl));
  std::vector<block> thirdU(mSenderSize);
  for (u64 k = 0; k < mSenderSize; ++k)
    thirdU[k] = thirdC[k] ^ sumPointShares(receiverShares, k, mDim);
  macoro::sync_wait(chl.send(std::move(thirdU)));

  SilentVoleSender<block, block> fourthVoleSender;
  AlignedUnVector<block> fourthD(mSenderSize);
  macoro::sync_wait(
      fourthVoleSender.silentSend(mVoleDelta, fourthD, prng, chl));
  std::vector<block> fourthV(mSenderSize), fourthW(mSenderSize);
  macoro::sync_wait(chl.recv(fourthV));
  for (u64 k = 0; k < mSenderSize; ++k)
    fourthW[k] = mVoleDelta.gf128Mul(fourthV[k] ^ thirdA[k]) ^ fourthD[k];
  macoro::sync_wait(chl.send(std::move(fourthW)));
  co_await chl.flush();
}

} // namespace CmpFuzzyPSI
