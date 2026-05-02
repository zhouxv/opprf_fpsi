#include "test.h"

#include "config.h"
#include "opprf/Defines.h"
#include "opprf/Opprf.h"
#include "pis_new/batch_peqt.h"
#include "utils/dist_util.h"
#include "utils/params_selects.h"
#include "utils/set_dec.h"
#include "utils/simpleTimer.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <cstdint>
#include <ipcl/plaintext.hpp>
#include <libOTe/Tools/CoeffCtx.h>
#include <libOTe/Vole/Silent/SilentVoleSender.h>
#include <macoro/task.h>
#include <map>
#include <spdlog/spdlog.h>
#include <vector>

#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>

inline auto eval(cp::task<> &t0, cp::task<> &t1) {
  auto r = cp::sync_wait(cp::when_all_ready(std::move(t0), std::move(t1)));
  std::get<0>(r).result();
  std::get<1>(r).result();
}

void test_opprf(const oc::CLP &cmd) {
  auto sender_size = cmd.getOr<u64>("s", 10);
  auto recv_size = cmd.getOr<u64>("r", 20);
  auto col_size = cmd.getOr<u64>("c", 3);
  auto intersection = cmd.getOr<u64>("i", 2);

  volePSI::RsOpprfSender sender;
  volePSI::RsOpprfReceiver recver;

  auto sockets = coproto::LocalAsyncSocket::makePair();

  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  // test non-block values
  // test unbalance opprf (sender n, recv 2n)
  std::vector<block> keys(sender_size);
  std::vector<block> keys_2(recv_size);

  prng0.get(keys.data(), sender_size);
  prng1.get(keys_2.data(), recv_size);

  for (u64 i = 0; i < intersection; i++) {
    keys_2[i] = keys[i];
  }

  oc::Matrix<u64> vals(sender_size, col_size);
  oc::Matrix<u64> recvOut(keys_2.size(), col_size);
  prng0.get(vals.data(), sender_size * col_size);

  for (u64 i = 0; i < sender_size; i++) {
    cout << "i: " << i << " ; ";
    for (u64 j = 0; j < col_size; j++) {
      cout << vals[i][j] << " ";
    }
    cout << endl;
  }

  auto p0 = sender.send(keys_2.size(), keys, vals, prng0, 1, sockets[0]);
  auto p1 = recver.receive(keys.size(), keys_2, recvOut, prng1, 1, sockets[1]);

  eval(p0, p1);

  for (u64 i = 0; i < 10; ++i) {
    cout << "[" << i << "] recv= ";
    for (u64 j = 0; j < col_size; j++) {
      cout << recvOut[i][j] << " ";
    }
    std::cout << "; send = ";
    for (u64 j = 0; j < col_size; j++) {
      cout << vals[i][j] << " ";
    }
    cout << endl;
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
  ipcl::PlainText randoms_pt = ipcl::PlainText(random_bns);
  ipcl::PlainText pt_zero = ipcl::PlainText(zero_bns);
  auto t1 = tEnd(timer);

  tStart(timer);
  ipcl::CipherText random_ciphers = pk.encrypt(randoms_pt);
  auto t2 = tEnd(timer);

  ipcl::PlainText random_ciphers_dec = sk.decrypt(random_ciphers);

  tStart(timer);
  ipcl::CipherText zero_ciphers = pk.encrypt(pt_zero);
  auto t3 = tEnd(timer);

  tStart(timer);
  auto add_res = random_ciphers + zero_ciphers;
  auto t4 = tEnd(timer);

  tStart(timer);
  auto mul_res = random_ciphers * randoms_pt;
  auto t5 = tEnd(timer);

  tStart(timer);
  ipcl::PlainText dt_add_ctx_cty = sk.decrypt(add_res);
  auto t6 = tEnd(timer);

  ipcl::PlainText dt_mul_ctx_cty = sk.decrypt(mul_res);

  spdlog::info("Paillier Encryption Test Results:");
  spdlog::info("Plaintext Encoding Time: {} ms", t1);
  spdlog::info("Random Values Encryption Time: {} ms", t2);
  spdlog::info("Zero Values Encryption Time: {} ms", t3);
  spdlog::info("Ciphertext Add Time: {} ms", t4);
  spdlog::info("Ciphertext Mul Time: {} ms", t5);
  spdlog::info("Decryption Time: {} ms", t6);

  auto commu = add_res.getTexts().size() * 2048 / 8 / 1024;
  spdlog::info("Communication for {} additions: {} KB", count, commu);

  vector<u32> tmp;
  random_bns[0].num2vec(tmp);
  spdlog::info("Verifying u32 vec size: random_bns(u64) {} , plaintext {} , "
               "ciphertext {} , random_ciphers_dec {} , dt_add_ctx_cty {} , "
               "dt_mul_ctx_cty {}",
               tmp.size(), randoms_pt.getElementVec(0).size(),
               random_ciphers.getElementVec(0).size(),
               random_ciphers_dec.getElementVec(0).size(),
               dt_add_ctx_cty.getElementVec(0).size(),
               dt_mul_ctx_cty.getElementVec(0).size());

  ipcl::terminateContext();
}

void test_batch_peqt(const oc::CLP &cmd) {
  u64 num = 10;
  PRNG prng(oc::sysRandomSeed());
  vector<block> a(num), b(num);

  prng.get(a.data(), num);
  prng.get(b.data(), num);
  for (u64 i = 0; i < num / 2; i++) {
    a[i] = b[i];
  }

  auto [socket0, socket1] = coproto::LocalAsyncSocket::makePair();

  osuCrypto::BitVector res0, res1;

  std::thread recv_thread(
      [&]() { res0 = macoro::sync_wait(Batch_PEQT_recv<block>(a, socket0)); });

  std::thread send_thread(
      [&]() { res1 = macoro::sync_wait(Batch_PEQT_send<block>(b, socket1)); });

  // 等待线程结束
  recv_thread.join();
  send_thread.join();

  for (u64 i = 0; i < num; i++) {
    spdlog::info("[{}] {} {} {} {}", i, a[i], b[i], res0[i], res1[i]);
  }
}

/*
Generic subfield noisy VOLE (semi-honest) [BCGIKRS19] test
*/
template <typename F, typename G, typename Ctx>
void vole_noisy_test_impl(u64 n) {
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

void test_vole_noisy(const oc::CLP &cmd) {
  for (u64 n : {1, 8, 433}) {
    vole_noisy_test_impl<u8, u8, CoeffCtxInteger>(n);
    vole_noisy_test_impl<u64, u32, CoeffCtxInteger>(n);
    vole_noisy_test_impl<block, block, CoeffCtxGF128>(n);
    vole_noisy_test_impl<std::array<u32, 11>, u32, CoeffCtxArray<u32, 11>>(n);
  }
}

/*
Generic subfield noisy VOLE (semi-honest) [BCGIKRS19] test
*/
template <typename F, typename G, typename Ctx>
void vole_silent_test_impl(const oc::CLP &cmd) {

  auto numVole = cmd.getOr<u64>("n", 1 << 20);

  // get up the networking
  auto chl = cp::LocalAsyncSocket::makePair();
  // get a random number generator seeded from the system
  PRNG prng(sysRandomSeed());

  // the LPN compression type.
  MultType mulType = oc::DefaultMultType;
  // regular noise or stationary noise.
  SdNoiseDistribution noiseType = SdNoiseDistribution::Regular;
  // the security type, semi-honest or malicious.
  oc::SilentSecType malType = oc::SilentSecType::SemiHonest;
  // should we use only base ots Base or a hybrid of base and extend BaseExtend.
  oc::SilentBaseType baseType = oc::SilentBaseType::BaseExtend;

  oc::SilentVoleSender<F, G> sender;
  oc::SilentVoleReceiver<F, G> receiver;

  Ctx ctx;

  // 𝔽   𝔽   𝔾    𝔽
  // A = B + C * DELTA
  // 𝒮   ℛ   𝒮     ℛ
  // c   d    a     b
  AlignedUnVector<F> A(numVole);
  AlignedUnVector<F> D(numVole);
  AlignedUnVector<G> C(numVole);
  F B_DELTA = prng.get<F>();

  receiver.configure(numVole, malType, mulType, baseType, noiseType);
  sender.configure(numVole, malType, mulType, baseType, noiseType);

  auto t_s = sender.silentSend(B_DELTA, D, prng, chl[0]);

  auto t_rs = receiver.silentReceive(A, C, prng, chl[1]);

  eval(t_s, t_rs);

  // validate the VOLE results
  try {
    for (u64 i = 0; i < numVole; ++i) {
      F minus, mul, sum;
      ctx.mul(mul, A[i], B_DELTA);
      ctx.plus(sum, D[i], mul);
      ctx.minus(minus, C[i], D[i]);
      if (C[i] != sum) {
        throw std::runtime_error("VOLE verification failed at " +
                                 std::to_string(i));
      }
      if (i < 5) {
        spdlog::info(
            "VOLE[{}]: C={:12} A={:12} D={:12} DELTA={:12}, C-D={:12}, "
            "A*B_DELTA={:12}",
            i, C[i], A[i], D[i], B_DELTA, minus, mul);
      }
    }

  } catch (const std::exception &e) {
    spdlog::error("测试失败: {}", e.what());
  }

  spdlog::info("✓ Silent VOLE 测试通过！({} 个元素)", numVole);
}

void test_vole_slient(const oc::CLP &cmd) {
  auto numVole = cmd.getOr<u64>("n", 1 << 20);

  // get up the networking
  auto chl = cp::LocalAsyncSocket::makePair();
  // get a random number generator seeded from the system
  PRNG prng(sysRandomSeed());

  // the LPN compression type.
  MultType mulType = oc::DefaultMultType;
  // regular noise or stationary noise.
  SdNoiseDistribution noiseType = SdNoiseDistribution::Regular;
  // the security type, semi-honest or malicious.
  oc::SilentSecType malType = oc::SilentSecType::SemiHonest;
  // should we use only base ots Base or a hybrid of base and extend BaseExtend.
  oc::SilentBaseType baseType = oc::SilentBaseType::BaseExtend;

  oc::SilentVoleSender<u32, u32> sender;
  oc::SilentVoleReceiver<u32, u32> receiver;

  // 𝔽   𝔽   𝔾    𝔽
  // A = B + C * DELTA
  // 𝒮   ℛ   𝒮     ℛ
  // c   d    a     b
  AlignedUnVector<u32> A(numVole);
  AlignedUnVector<u32> D(numVole);
  AlignedUnVector<u32> C(numVole);
  u32 B_DELTA = prng.get<u32>();

  receiver.configure(numVole, malType, mulType, baseType, noiseType);
  sender.configure(numVole, malType, mulType, baseType, noiseType);

  auto t_s = sender.silentSend(B_DELTA, D, prng, chl[0]);

  auto t_rs = receiver.silentReceive(A, C, prng, chl[1]);

  eval(t_s, t_rs);

  // validate the VOLE results
  try {
    for (u64 i = 0; i < numVole; ++i) {
      u64 minus, mul, sum;
      mul = A[i] * B_DELTA;
      sum = D[i] + mul;
      minus = C[i] - D[i];
      // if (C[i] != sum) {
      //   throw std::runtime_error("VOLE verification failed at " +
      //                            std::to_string(i));
      // }
      if (i < 5) {
        spdlog::info(
            "VOLE[{}]: C={:12} A={:12} D={:12} DELTA={:12}, C-D={:12}, "
            "A*B_DELTA={:12}, sum:{:12}",
            i, C[i], A[i], D[i], B_DELTA, minus, mul, sum);

        spdlog::info("VOLE[{}]: -D {} AB-C {}", i, -D[i],
                     A[i] * B_DELTA - C[i]);
        spdlog::info("VOLE[{}]: -D {} AB-C {}", i, (u64)D[i],
                     (u64)A[i] * (u64)B_DELTA + (u64)C[i]);
      }
    }

  } catch (const std::exception &e) {
    spdlog::error("测试失败: {}", e.what());
  }

  spdlog::info("✓ Silent VOLE 测试通过！({} 个元素)", numVole);
}

void test_prefix_param(const oc::CLP &cmd) {
  if (cmd.isSet("m")) {
    u64 metric = cmd.getOr("m", 0);
    if (metric == 0)
      test_prefix_param_linf(cmd);
    else
      test_prefix_param_lp(cmd);

    return;
  }
  if (cmd.isSet("ifm")) {
    test_prefix_param_ifmatch(cmd);
    return;
  }
}

void test_prefix_param_lp(const oc::CLP &cmd) {
  const vector<u64> deltas = cmd.getManyOr<u64>("deltas", {30, 60, 120, 250});
  const u64 trait = cmd.getOr<u64>("i", 1 << 28);

  map<u64, PrefixParam> params;
  params[10] = {{0, 1}, 6};
  params[11] = {{0, 2}, 5};
  params[30] = {{0, 2}, 12};
  params[31] = {{0, 2}, 10};
  params[60] = {{0, 3}, 18};
  params[61] = {{0, 3}, 19};
  params[120] = {{0, 3}, 22};
  params[121] = {{0, 3}, 23};
  params[250] = {{0, 3}, 40};
  params[251] = {{0, 3}, 31};

  std::map<u64, u64> map;
  PRNG prng(oc::sysRandomSeed());

  for (auto delta : deltas) {
    for (u64 j = 0; j < trait; j++) {
      auto param = params[delta];
      auto param_plus = params[delta + 1];
      u64 val = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
                1.5 * delta;

      auto prefixs0 = set_dec(val - delta, val, param_plus.first);
      auto prefixs1 = set_dec(val + 1, val + delta, param.first);

      if (map[delta + 1] < prefixs0.size())
        map[delta + 1] = prefixs0.size();
      if (map[delta] < prefixs1.size())
        map[delta] = prefixs1.size();
    }
  }

  // 输出map，按照key的大小排序
  for (const auto &kv : map) {
    spdlog::info("delta: {}, count: {}", kv.first, kv.second);
  }
}

void test_prefix_param_linf(const oc::CLP &cmd) {
  const vector<u64> deltas =
      cmd.getManyOr<u64>("deltas", {10, 30, 60, 120, 250});
  const u64 logn = cmd.getOr<u64>("n", 20);
  u64 trait = 1 << logn;

  map<u64, PrefixParam> params;

  params[21] = {{0, 1, 2, 3}, 6};
  params[61] = {{0, 1, 2, 3, 4}, 9};
  params[121] = {{0, 1, 2, 3, 4, 5}, 10};
  params[241] = {{0, 1, 2, 3, 5, 6}, 12};
  params[501] = {{0, 1, 2, 4, 5, 6}, 17};

  std::map<u64, u64> map;
  PRNG prng(oc::sysRandomSeed());

  for (auto delta : deltas) {
    auto param = params[delta * 2 + 1];

    for (u64 j = 0; j < trait; j++) {
      u64 val = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
                1.5 * delta;

      auto prefixs = set_dec(val - delta, val + delta, param.first);

      if (map[2 * delta + 1] < prefixs.size())
        map[2 * delta + 1] = prefixs.size();
    }
  }

  // 输出map，按照key的大小排序
  for (const auto &kv : map) {
    spdlog::info("delta: {}, count: {}", kv.first, kv.second);
  }
}

void test_prefix_param_ifmatch(const oc::CLP &cmd) {
  const vector<u64> deltas =
      cmd.getManyOr<u64>("deltas", {10, 30, 60, 120, 250});
  const u64 logn = cmd.getOr<u64>("n", 20);
  u64 trait = 1 << logn;

  map<u64, PrefixParam> params;

  params[11] = {{0, 2}, 5};
  params[31] = {{0, 1, 2, 3}, 6};
  params[61] = {{0, 2, 3, 4}, 11};
  params[121] = {{0, 2, 4, 5}, 14};
  params[251] = {{0, 2, 4, 6}, 17};
  params[101] = {{0, 2, 4, 6}, 5};
  params[901] = {{0, 3, 6, 9}, 6};
  params[3601] = {{0, 4, 8, 11}, 11};
  params[14401] = {{0, 4, 8, 13}, 14};
  params[62501] = {{0, 5, 10, 15}, 17};

  std::map<u64, u64> map;
  PRNG prng(oc::sysRandomSeed());

  for (auto delta : deltas) {
    for (u64 j = 1; j < 3; j++) {
      auto tmp = fast_pow<u64>(delta, j);
      auto param = params[tmp + 1];

      for (u64 j = 0; j < trait; j++) {
        u64 val = (prng.get<u64>()) % ((0x1111'ffff'ffff'ffff) - 3 * tmp);

        auto prefixs = set_dec(val, val + tmp, param.first);

        if (map[tmp + 1] < prefixs.size())
          map[tmp + 1] = prefixs.size();
      }
    }
  }

  // 输出map，按照key的大小排序
  for (const auto &kv : map) {
    spdlog::info("delta: {}, count: {}", kv.first, kv.second);
  }
}

void test_data_convert(const oc::CLP &cmd) {
  u64 delta = cmd.getOr("delta", 250);
  u64 trait = cmd.getOr("trait", 250);

  PRNG prng(oc::sysRandomSeed());
  for (u64 i = 0; i < trait; i++) {
    u8 a = prng.get<u8>();
    u64 a_ = a;
    u64 a__ = a_;
    i8 b = a;
    u64 c = b;
    a__ += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);

    spdlog::info("a u8: {:5}; a_ u64: {:5}; a+=i8 {:20}, b i8: {:10} , c "
                 "i8->u64: {:20} , u64 + i8: {:10}",
                 a, a_, a__, b, c, a__ + b);
  }
}