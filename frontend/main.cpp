#include "config.h"
#include "fpsi_recv.h"
#include "fpsi_sender.h"
#include "test.h"
#include "utils/util.h"

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <fmt/format.h>
#include <fmt/ostream.h> // 包含这个以支持流输出
#include <ipcl/ipcl.hpp>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#define FMT_DEPRECATED_OSTREAM

enum class Role {
  Recv,  // receiver
  Sender // sender
};

void run_fmap_protocol(const CLP &cmd);
void run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                       const u64 DELTA, const u64 INTERSECTION_SIZE,
                       const u64 TRAIT, const string IP, const u64 PORT,
                       const bool COMP_IDX, const bool PTS_SAME);

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  /*
  spdlog logs setting
  0: no log
  1: info
  2: debug
  */
  //  Set up logs
  auto log_level = cmd.getOr<u64>("log", 1);

  // spdlog::set_pattern("[%l] %v");
  spdlog::set_pattern("%v");
  switch (log_level) {
  case 0:
    spdlog::set_level(spdlog::level::off);
    break;
  case 1:
    spdlog::set_level(spdlog::level::info);
    break;
  case 2:
    spdlog::set_level(spdlog::level::debug);
    break;
  default:
    spdlog::set_level(spdlog::level::info);
  }

  /*
  Unit tests
  1: test opprf
  2: test vole noisy
  */
  if (cmd.isSet("t")) {
    const u64 test_type = cmd.getOr("t", 0);
    switch (test_type) {
    case 1:
      test_opprf(cmd);
      break;
    case 2:
      test_Vole_Noisy(cmd);
      break;
    case 3:
      test_get_phi(cmd);
      break;
    default:
      spdlog::error("Unknown test type", test_type);
    }
    return 0;
  }

  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 1);
    switch (protocol_type) {
    case 1:
      run_fmap_protocol(cmd);
      break;
    default:
      spdlog::error("Unknown protocol type", protocol_type);
    }
  }

  return 0;
}

void run_fmap_protocol(const CLP &cmd) {
  /*
  run fmap protocol
  */
  // obtain protocol parameters
  const vector<u64> nums = cmd.getManyOr<u64>("n", {8});
  const vector<u64> dims = cmd.getManyOr<u64>("d", {2});
  const vector<u64> metrics = cmd.getManyOr<u64>("m", {0});
  const vector<u64> deltas = cmd.getManyOr<u64>("delta", {10});
  const u64 intersection_size = cmd.getOr("i", 15);
  const u64 trait = cmd.getOr("trait", 3);
  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);
  const bool fm_old = cmd.isSet("fm_old");
  const bool pts_same = cmd.isSet("same");

  // run fmap protocol
  for (auto num : nums) { // set size
    auto set_size = 1 << num;
    for (auto dim : dims) {         // d
      for (auto metric : metrics) { // p
        for (auto delta : deltas) { // delta
          run_fmap_protocol(set_size, dim, metric, delta, intersection_size,
                            trait, ip, port, fm_old, pts_same);
        }
        std::cout << std::endl;
      }
    }
  }
}

void run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                       const u64 DELTA, const u64 INTERSECTION_SIZE,
                       const u64 TRAIT, const string IP, const u64 PORT,
                       const bool FM_OLD, const bool PTS_SAME) {

  if (INTERSECTION_SIZE > PT_NUM) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("*********************** setting ****************************");
  spdlog::info("set_size          : {}", PT_NUM);
  spdlog::info("dimension         : {} ", DIM);
  spdlog::info("metric            : l_{} ", METRIC);
  spdlog::info("delta             : {} ", DELTA);
  spdlog::info("intersection_size : {}", INTERSECTION_SIZE);
  spdlog::info("trait             : {}", TRAIT);
  spdlog::info("fmap_old          : {}", FM_OLD);
  spdlog::info("pts_same          : {}", PTS_SAME);

  // Paillier keys initialization
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();
  spdlog::info("Paillier keys initialization finished");

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < 1; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();

  spdlog::info("Network communication initialization finished");

  // Both parties point set sampling
  vector<pt> recv_pts(PT_NUM, vector<u64>(DIM, 0));
  vector<pt> send_pts(PT_NUM, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, PT_NUM, PT_NUM, INTERSECTION_SIZE, send_pts,
                recv_pts, PTS_SAME);

  spdlog::info("Both parties point set sampling finished");

  FPSIRecv recv(DIM, DELTA, PT_NUM, METRIC, 1, recv_pts, paillier_key.pub_key,
                paillier_key.priv_key, socketPair0);
  FPSISender sender(DIM, DELTA, PT_NUM, METRIC, 1, send_pts, socketPair1);

  vector<double> time_sums(TRAIT, 0);
  vector<double> comm_sums(TRAIT, 0.0);

  if (FM_OLD) {
    sender.DFmap_fig8_offline();
    recv.DFmap_fig8_offline();
  } else {
    sender.DFmap_fig9_offline();
    recv.DFmap_fig9_offline();
  }

  spdlog::info("Fmap Offline phase finished");

  for (u64 i = 0; i < TRAIT; i++) {
    // Use std::bind to bind member function and object
    simpleTimer timer;

    timer.start();

    if (FM_OLD) {
      std::thread recv_msg(std::bind(&FPSIRecv::DFmap_fig8_online, &recv));
      std::thread send_msg(std::bind(&FPSISender::DFmap_fig8_online, &sender));
      recv_msg.join();
      send_msg.join();
    } else {
      std::thread recv_msg(std::bind(&FPSIRecv::DFmap_fig9_online, &recv));
      std::thread send_msg(std::bind(&FPSISender::DFmap_fig9_online, &sender));
      recv_msg.join();
      send_msg.join();
    }

    spdlog::info("Fmap Online phase finished");

    timer.end("protocol_online");

    auto online_time = timer.get_by_key("protocol_online");
    time_sums[i] = online_time;
    comm_sums[i] = socketPair0[0].bytesReceived() + socketPair0[0].bytesSent();

    for (u64 i = 0; i < 10; i++) {
      spdlog::debug("ID[{}] {} {}", i, recv.ID_xr[i], sender.ID_ys[i]);
    }

    recv.clear();
    sender.clear();
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / 1000.0 / TRAIT;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) /
                   1024.0 / 1024.0 / TRAIT;

  if (FM_OLD) {
    cout << std::format(
                "[fig8_fmap]  {:^5}  𝐿{}  {:^5}  {:^5}  {:^10.3f}  {:^10.3f}",
                PT_NUM, METRIC, DIM, DELTA, avg_online_time, avg_com)
         << endl;
  } else {
    cout << std::format(
                "[fig9_fmap]  {:^5}  𝐿{}  {:^5}  {:^5}  {:^10.3f}  {:^10.3f}",
                PT_NUM, METRIC, DIM, DELTA, avg_online_time, avg_com)
         << endl;
  }

  return;
}