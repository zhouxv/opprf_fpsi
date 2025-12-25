
#include "test.h"

#include "config.h"
#include "opprf/Opprf.h"
#include "utils/simpleTimer.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <macoro/task.h>
#include <spdlog/spdlog.h>
#include <vector>

#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>

inline auto eval(macoro::task<> &t0, macoro::task<> &t1) {
  auto r =
      macoro::sync_wait(macoro::when_all_ready(std::move(t0), std::move(t1)));
  std::get<0>(r).result();
  std::get<1>(r).result();
}

/*
Generic subfield noisy VOLE (semi-honest) [BCGIKRS19] test
*/
template <typename F, typename G, typename Ctx>
void Vole_Noisy_test_impl(u64 n) {
  PRNG prng(CCBlock);

  F delta = prng.get();
  std::vector<G> c(n);
  std::vector<F> a(n), b(n);
  prng.get(c.data(), c.size());

  NoisyVoleReceiver<F, G, Ctx> recv;
  NoisyVoleSender<F, G, Ctx> send;

  auto chls = cp::LocalAsyncSocket::makePair();

  Ctx ctx;
  BitVector recvChoice = ctx.binaryDecomposition(delta);
  std::vector<block> otRecvMsg(recvChoice.size());
  std::vector<std::array<block, 2>> otSendMsg(recvChoice.size());
  prng.get<std::array<block, 2>>(otSendMsg);
  for (u64 i = 0; i < recvChoice.size(); ++i)
    otRecvMsg[i] = otSendMsg[i][recvChoice[i]];

  // compute a,b such that
  //
  //   a = b + c * delta
  //
  auto p0 = recv.receive(c, a, prng, otSendMsg, chls[0], ctx);
  auto p1 = send.send(delta, b, prng, otRecvMsg, chls[1], ctx);

  eval(p0, p1);

  for (u64 i = 0; i < n; ++i) {
    F prod, sum;

    ctx.mul(prod, delta, c[i]);
    ctx.minus(sum, a[i], b[i]);

    if (prod != sum) {
      throw RTE_LOC;
    }
  }
}

void test_opprf(const oc::CLP &cmd) {

  volePSI::RsOpprfSender sender;
  volePSI::RsOpprfReceiver recver;

  auto sockets = coproto::LocalAsyncSocket::makePair();

  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), out(n);

  prng0.get(vals.data(), n);
  prng0.get(out.data(), n);

  std::vector<block> vals_2(2 * n);
  prng1.get(vals_2.data(), 2 * n);
  std::vector<block> recvOut(vals_2.size());

  auto p0 = sender.send(vals_2.size(), vals, out, prng0, 1, sockets[0]);
  auto p1 = recver.receive(vals.size(), vals_2, recvOut, prng1, 1, sockets[1]);

  eval(p0, p1);

  u64 count = 0;
  for (u64 i = 0; i < 10; ++i) {
    auto v = sender.eval<block>(vals[i]);

    if (count < 10) {
      std::cout << i << " recv= " << recvOut[i] << ", send = " << v
                << ", send* = " << out[i] << std::endl;
    } else {
      break;
    }

    ++count;
  }
}

void test_Vole_Noisy(const oc::CLP &cmd) {
  for (u64 n : {1, 8, 433}) {
    Vole_Noisy_test_impl<u8, u8, CoeffCtxInteger>(n);
    Vole_Noisy_test_impl<u64, u32, CoeffCtxInteger>(n);
    Vole_Noisy_test_impl<block, block, CoeffCtxGF128>(n);
    Vole_Noisy_test_impl<std::array<u32, 11>, u32, CoeffCtxArray<u32, 11>>(n);
  }
}

void test_pailliar(const oc::CLP &cmd) {
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  auto pk = paillier_key.pub_key;
  auto sk = paillier_key.priv_key;

  u64 count = cmd.getOr("n", 10000);

  // Generate random values and zero values
  vector<u64> zero_values(count, 0);
  vector<u64> random_values(count, 0);
  vector<BigNumber> random_bns(count, 0);
  vector<BigNumber> zero_bns(count, 0);

  PRNG prng(oc::sysRandomSeed());
  prng.get(random_values.data(), random_values.size());

  for (u64 i = 0; i < count; i++) {
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
    zero_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&zero_values[i]), 2);
  }

  tVar timer;

  tStart(timer);
  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  ipcl::PlainText pt_zero = ipcl::PlainText(zero_bns);
  auto t1 = tEnd(timer);

  tStart(timer);
  ipcl::CipherText random_ciphers = pk.encrypt(pt_randoms);
  auto t2 = tEnd(timer);

  tStart(timer);
  ipcl::CipherText zero_ciphers = pk.encrypt(pt_zero);
  auto t3 = tEnd(timer);

  tStart(timer);
  auto add_res = random_ciphers + zero_ciphers;
  auto t4 = tEnd(timer);

  tStart(timer);
  ipcl::PlainText dt_add_ctx_cty = sk.decrypt(add_res);
  auto t5 = tEnd(timer);

  spdlog::info("Paillier Encryption Test Results:");
  spdlog::info("Plaintext Encoding Time: {} ms", t1);
  spdlog::info("Random Values Encryption Time: {} ms", t2);
  spdlog::info("Zero Values Encryption Time: {} ms", t3);
  spdlog::info("Ciphertext Addition Time: {} ms", t4);
  spdlog::info("Decryption Time: {} ms", t5);

  auto commu = add_res.getTexts().size() * 2048 / 8 / 1024;
  spdlog::info("Communication for {} additions: {} KB", count, commu);

  ipcl::terminateContext();
}
