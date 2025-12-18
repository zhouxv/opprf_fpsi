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
#include <fmt/ostream.h>
#include <ipcl/ipcl.hpp>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>
#include <utility>

// usr for print block data
#define FMT_DEPRECATED_OSTREAM 1

enum class Role {
  Recv,  // receiver
  Sender // sender
};

void run_fmap_protocol(const CLP &cmd);
std::pair<double, double>
run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                  const u64 DELTA, const u64 INTERSECTION_SIZE, const string IP,
                  const u64 PORT, const bool COMP_IDX, const bool PTS_SAME,
                  const bool DETAILED, const bool FAKE);

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
    case 4:
      test_pailliar(cmd);
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
  const bool detailed = cmd.isSet("detail");
  const bool fake = cmd.isSet("fake");

  // run fmap protocol
  for (auto num : nums) { // set size

    // check intersection size
    auto set_size = 1 << num;
    if (intersection_size > set_size) {
      spdlog::error("intersection_size should not be greater than set_size");
      return;
    }

    for (auto dim : dims) {         // d
      for (auto metric : metrics) { // p
        for (auto delta : deltas) { // delta

          spdlog::info(
              "*********************** setting ****************************");
          spdlog::info("set_size          : {}", set_size);
          spdlog::info("dimension         : {} ", dim);
          spdlog::info("metric            : l_{} ", metric);
          spdlog::info("delta             : {} ", delta);
          spdlog::info("intersection_size : {}", intersection_size);
          spdlog::info("trait             : {}", trait);
          spdlog::info("fmap_old          : {}", fm_old);
          spdlog::info("pts_same          : {}", pts_same);
          spdlog::info("detailed          : {}", detailed);
          spdlog::info("fake              : {}", fake);

          vector<double> time_sums(trait, 0);
          vector<double> comm_sums(trait, 0.0);
          for (u64 i = 0; i < trait; i++) {
            auto tmp = run_fmap_protocol(set_size, dim, metric, delta,
                                         intersection_size, ip, port, fm_old,
                                         pts_same, detailed, fake);
            time_sums[i] = tmp.first;
            comm_sums[i] = tmp.second;
          }

          double avg_online_time =
              accumulate(time_sums.begin(), time_sums.end(), 0.0) / 1000.0 /
              trait;

          double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) /
                           1024.0 / 1024.0 / trait;

          if (fm_old) {
            cout << std::format("[fig8_fmap]  {:^5}  𝐿{}  {:^5}  {:^5}  "
                                "{:^10.3f}  {:^10.3f}",
                                set_size, metric, dim, delta, avg_online_time,
                                avg_com)
                 << endl;
          } else {
            cout << std::format("[fig9_fmap]  {:^5}  𝐿{}  {:^5}  {:^5}  "
                                "{:^10.3f}  {:^10.3f}",
                                set_size, metric, dim, delta, avg_online_time,
                                avg_com)
                 << endl;
          }
        }
        std::cout << std::endl;
      }
    }
  }
}

std::pair<double, double>
run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                  const u64 DELTA, const u64 INTERSECTION_SIZE, const string IP,
                  const u64 PORT, const bool FM_OLD, const bool PTS_SAME,
                  const bool DETAILED, const bool FAKE) {
  simpleTimer timer;

  // Paillier keys initialization
  ipcl::initializeContext("QAT");
  ipcl::KeyPair fmap_recv = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair fmap_sender = ipcl::generateKeypair(2048, true);
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

  FPSIRecv recv(DIM, DELTA, PT_NUM, METRIC, 1, recv_pts, fmap_recv, fmap_sender,
                socketPair0);
  FPSISender sender(DIM, DELTA, PT_NUM, METRIC, 1, send_pts, fmap_recv,
                    fmap_sender, socketPair1);

  timer.start();
  if (FM_OLD) {
    sender.DFmap_fig8_offline();
    recv.DFmap_fig8_offline();
  } else {
    if (FAKE) {
      sender.DFmap_fig9_offline_fake();
      recv.DFmap_fig9_offline_fake();
    } else {
      sender.DFmap_fig9_offline();
      recv.DFmap_fig9_offline();
    }
  }
  timer.end("protocol_offline");
  spdlog::info("Fmap Offline phase finished !!");

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

  spdlog::info("Fmap Online phase finished !!");

  timer.end("protocol_online");

  auto recv_com = recv.commus;
  auto sender_com = sender.commus;

  // double total_com = 0.0;
  // for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
  //   total_com += it->second;
  // }
  // for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
  //   total_com += it->second;
  // }
  // cout << "Total communication in online phase: "
  //      << total_com / 1024.0 / 1024.0 << " MB" << endl;

  auto offline_time = timer.get_by_key("protocol_offline");
  auto online_time = timer.get_by_key("protocol_online");
  auto total_com =
      socketPair0[0].bytesReceived() + socketPair1[0].bytesReceived();

  spdlog::info("*********************** Result ****************************");
  spdlog::info("Offline time (s)           : {:.3f} ", offline_time / 1000.0);
  spdlog::info("Online time (s)            : {:.3f} ", online_time / 1000.0);
  spdlog::info("Total communication (MB)   : {:.3f} ",
               total_com / 1024.0 / 1024.0);
  if (DETAILED) {
    spdlog::info("***********************************************************");
    sender.print_commus();
    spdlog::info("***********************************************************");
    sender.print_time();
    spdlog::info("***********************************************************");
    recv.print_commus();
    spdlog::info("***********************************************************");
    recv.print_time();
  }
  spdlog::info("***********************************************************");
  return {online_time, total_com};
}