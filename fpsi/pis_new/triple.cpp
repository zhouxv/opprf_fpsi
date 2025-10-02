#include "pis_new/triple.h"
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>

u64 otStep = 1ull << 24;
bool silent = false;

coproto::task<> triple0(coproto::Socket &chl, BitVector &a0, BitVector &b0,
                        BitVector &c0) {
  PRNG prng(sysRandomSeed());
  u64 n = a0.size();
  b0.randomize(prng);

  IknpOtExtSender sender;
  IknpOtExtReceiver receiver;
  SilentOtExtSender silentSender;
  SilentOtExtReceiver silentReceiver;

  // virtual channels, share chl
  auto sendChl = chl.fork();
  auto recvChl = chl.fork();

  vector<array<block, 2>> sendMsg;
  vector<block> recvMsg;
  BitVector tmpb0;
  for (u64 j = 0; j < n; j += otStep) {
    u64 curStep = std::min(otStep, n - j);
    sendMsg.resize(curStep);
    recvMsg.resize(curStep);
    tmpb0.resize(curStep);
    if (silent) {
      auto taskSend =
          silentSender.send(sendMsg, prng, sendChl) | macoro::make_eager();
      auto taskRecv = silentReceiver.receive(tmpb0, recvMsg, prng, recvChl) |
                      macoro::make_eager();
      co_await std::move(taskSend);
      co_await std::move(taskRecv);
    } else {
      auto taskSend =
          sender.send(sendMsg, prng, sendChl) | macoro::make_eager();
      auto taskRecv = receiver.receive(tmpb0, recvMsg, prng, recvChl) |
                      macoro::make_eager();
      co_await std::move(taskSend);
      co_await std::move(taskRecv);
    }

    for (u64 i = 0; i < curStep; i++) {
      bool x = block_to_bool(sendMsg[i][0]) ^ block_to_bool(sendMsg[i][1]);
      a0[j + i] = x;
      bool z = block_to_bool(sendMsg[i][0]) ^ (x & tmpb0[i]) ^
               block_to_bool(recvMsg[i]);
      c0[j + i] = z;
    }
    memcpy(b0.data() + (j >> 3), tmpb0.data(), (curStep + 7) >> 3);
  }

  co_await sendChl.flush();
  co_await recvChl.flush();
}

coproto::task<> triple1(coproto::Socket &chl, BitVector &a1, BitVector &b1,
                        BitVector &c1) {
  PRNG prng(sysRandomSeed());
  u64 n = a1.size();
  b1.randomize(prng);

  IknpOtExtSender sender;
  IknpOtExtReceiver receiver;
  SilentOtExtSender silentSender;
  SilentOtExtReceiver silentReceiver;

  auto recvChl = chl.fork();
  auto sendChl = chl.fork();
  vector<block> recvMsg;
  vector<array<block, 2>> sendMsg;
  BitVector tmpb1;
  for (u64 j = 0; j < n; j += otStep) {
    u64 curStep = std::min(otStep, n - j);
    sendMsg.resize(curStep);
    recvMsg.resize(curStep);
    tmpb1.resize(curStep);
    if (silent) {
      auto taskRecv = silentReceiver.receive(tmpb1, recvMsg, prng, recvChl) |
                      macoro::make_eager();
      auto taskSend =
          silentSender.send(sendMsg, prng, sendChl) | macoro::make_eager();
      co_await std::move(taskRecv);
      co_await std::move(taskSend);
    } else {
      auto taskRecv = receiver.receive(tmpb1, recvMsg, prng, recvChl) |
                      macoro::make_eager();
      auto taskSend =
          sender.send(sendMsg, prng, sendChl) | macoro::make_eager();
      co_await std::move(taskRecv);
      co_await std::move(taskSend);
    }

    for (u64 i = 0; i < curStep; i++) {
      bool x = block_to_bool(sendMsg[i][0]) ^ block_to_bool(sendMsg[i][1]);
      a1[j + i] = x;
      bool z = block_to_bool(sendMsg[i][0]) ^ (x & tmpb1[i]) ^
               block_to_bool(recvMsg[i]);
      c1[j + i] = z;
    }
    memcpy(b1.data() + (j >> 3), tmpb1.data(), (curStep + 7) >> 3);
  }

  co_await recvChl.flush();
  co_await sendChl.flush();
}
