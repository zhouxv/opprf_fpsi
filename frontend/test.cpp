
#include "test.h"

#include "config.h"
#include "opprf/Opprf.h"
#include "utils/util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <macoro/task.h>
#include <spdlog/spdlog.h>
#include <vector>

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

  std::vector<block> vals_2(vals.begin(), vals.begin() + n / 2);
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

void test_get_phi(const oc::CLP &cmd) {
  auto num = cmd.getOr("n", 8);
  auto dim = cmd.getOr("d", 2);
  auto delta = cmd.getOr("delta", 10);
  auto trait = cmd.getOr("trait", 10);
  auto pt_num = 1 << num;
  vector<pt> pts(pt_num, vector<u64>(dim, 0));

  cout << "pt_num: " << pt_num << ", dim: " << dim << " , delta: " << delta
       << endl;

  u64 count = 0;
  for (u64 i = 0; i < trait; i++) {
    PRNG prng(oc::sysRandomSeed());

    for (u64 i = 0; i < pt_num; i++) {
      for (u64 j = 0; j < dim; j++) {
        pts[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
                    1.5 * delta;
      }
    }

    auto phi = get_phi_dim_optimized(pts, delta);
    if (phi[0] == 0)
      count++;
  }
  cout << "count: " << count << endl;
}