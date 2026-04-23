#include "fpsi_protocol.h"
#include "fpsi_recv.h"
#include "fpsi_sender.h"
#include "utils/dist_util.h"
#include "utils/simpleTimer.h"

#include <utility>

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <ipcl/ipcl.hpp>
#include <spdlog/spdlog.h>

void run_fmap_protocol(const CLP &cmd) {
  // obtain protocol parameters
  const vector<u64> nums = cmd.getManyOr<u64>("n", {8});
  const vector<u64> dims = cmd.getManyOr<u64>("d", {2});
  const vector<u64> metrics = cmd.getManyOr<u64>("m", {0});
  const vector<u64> deltas = cmd.getManyOr<u64>("delta", {10});
  const u64 intersection_size = cmd.getOr("i", 15);
  const u64 trait = cmd.getOr("trait", 1);
  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  const bool fm_type = cmd.getOr("fm", 0);
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
          spdlog::info("delta             : {} ", delta);
          spdlog::info("intersection_size : {}", intersection_size);
          spdlog::info("trait             : {}", trait);
          spdlog::info("fmap_type         : {}",
                       fm_type ? "fig8-(d,d) DFmap" : "fig9-(1,1) DFmap");
          spdlog::info("pts_same          : {}", pts_same);
          spdlog::info("detailed          : {}", detailed);
          spdlog::info("fake              : {}", fake);
          spdlog::info(
              "***********************************************************");

          vector<double> time_sums(trait, 0);
          vector<double> comm_sums(trait, 0.0);
          for (u64 i = 0; i < trait; i++) {
            auto tmp =
                run_fmap_protocol(set_size, dim, delta, intersection_size, ip,
                                  port, fm_type, pts_same, detailed, fake);
            time_sums[i] = tmp.first;
            comm_sums[i] = tmp.second;
          }

          double avg_online_time =
              accumulate(time_sums.begin(), time_sums.end(), 0.0) / 1000.0 /
              trait;

          double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) /
                           1024.0 / 1024.0 / trait;

          //  print result
          string pro_type = (fm_type) ? "fig8_fmap" : "fig9_fmap";

          cout << std::format("[{}]  {:^5}  {:^5}  {:^5}  "
                              "{:^10.3f}  {:^10.3f}",
                              pro_type, set_size, dim, delta, avg_com,
                              avg_online_time)
               << endl;
        }
        std::cout << std::endl;
      }
    }
  }
}

std::pair<double, double>
run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 DELTA,
                  const u64 INTERSECTION_SIZE, const string IP, const u64 PORT,
                  const bool FM_TYPE, const bool PTS_SAME, const bool DETAILED,
                  const bool FAKE) {
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

  // FPSI objects initialization
  FPSIRecv recv(DIM, DELTA, PT_NUM, 0, 1, recv_pts, fmap_recv, fmap_sender,
                socketPair0);
  FPSISender sender(DIM, DELTA, PT_NUM, 0, 1, send_pts, fmap_recv, fmap_sender,
                    socketPair1);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Fmap Offline phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto fmap_offline = [&](FPSISender &s, FPSIRecv &r, bool fm_type, bool fake) {
    // figure 8 DFmap offline phase
    if (fm_type) {
      s.DFmap_fig8_offline();
      r.DFmap_fig8_offline();
      return;
    }
    // figure 9 DFmap offline phase
    if (fake) {
      s.DFmap_fig9_offline_fake();
      r.DFmap_fig9_offline_fake();
      return;
    } else {
      s.DFmap_fig9_offline();
      r.DFmap_fig9_offline();
      return;
    }
  };

  timer.start();
  fmap_offline(sender, recv, FM_TYPE, FAKE);
  timer.end("protocol_offline");
  spdlog::info("Fmap Offline phase finished !!");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Fmap Online phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  timer.start();
  if (FM_TYPE) {
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
  timer.end("protocol_online");
  spdlog::info("Fmap Online phase finished !!");

  // for (u64 i = 0; i < 10; i++) {
  //   spdlog::debug("IDs[{}] {} {}", i, recv.fig9_ID_xr[i],
  //   sender.fig9_ID_ys[i]);
  // }

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Result statistics
  /*--------------------------------------------------------------------------------------------------------------------------------*/
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
  spdlog::info("***********************************************************");
  if (DETAILED) {
    sender.print_commus();
    spdlog::info("***********************************************************");
    sender.print_time();
    spdlog::info("***********************************************************");
    recv.print_commus();
    spdlog::info("***********************************************************");
    recv.print_time();
    spdlog::info("***********************************************************");
    auto count = 0;
    // for (u64 i = 0; i < PT_NUM; i++) {
    //   spdlog::debug("[{}] {} {} {}", i, recv.fig9_ID_xr[i],
    //                 sender.fig9_ID_ys[i],
    //                 recv.fig9_ID_xr[i] == sender.fig9_ID_ys[i]);
    //   if (recv.fig9_ID_xr[i] == sender.fig9_ID_ys[i])
    //     count++;
    // }
    // spdlog::debug("fmap count: {}", count);
  }

  return {online_time, total_com};
}

void run_fpsi_protocol(const CLP &cmd) {
  // obtain protocol parameters
  const u64 num = cmd.getOr<u64>("n", 8);
  const u64 dim = cmd.getOr<u64>("d", 2);
  const u64 metric = cmd.getOr<u64>("m", 0);
  const u64 delta = cmd.getOr<u64>("delta", 10);
  const u64 intersection_size = cmd.getOr("i", 15);
  const u64 trait = cmd.getOr("trait", 1);
  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  const bool fm_type = cmd.getOr("fm", 0);
  const bool pts_same = cmd.isSet("same");
  const bool detailed = cmd.isSet("detail");
  const bool fake = cmd.isSet("fake");

  // check intersection size
  auto set_size = 1 << num;
  if (intersection_size > set_size) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  // obtain protocol parameters
  spdlog::info("*********************** setting ****************************");
  spdlog::info("set_size          : {}", set_size);
  spdlog::info("dimension         : {} ", dim);
  spdlog::info("metric            : l_{} ", metric);
  spdlog::info("delta             : {} ", delta);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("trait             : {}", trait);

  spdlog::info("fmap_type         : {}",
               fm_type ? "fig8-(d,d) DFmap" : "fig9-(1,1) DFmap");
  spdlog::info("pts_same          : {}", pts_same);
  spdlog::info("detailed          : {}", detailed);
  spdlog::info("fake              : {}", fake);
  spdlog::info("***********************************************************");

  vector<double> time_sums(trait, 0);
  vector<double> comm_sums(trait, 0.0);
  for (u64 i = 0; i < trait; i++) {
    std::pair<double, double> tmp =
        run_fpsi_protocol(set_size, dim, metric, delta, intersection_size, ip,
                          port, fm_type, pts_same, detailed, fake);
    time_sums[i] = tmp.first;
    comm_sums[i] = tmp.second;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / 1000.0 / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) /
                   1024.0 / 1024.0 / trait;

  string pro_type = (fm_type) ? "fig8_fpsi" : "fig9_fpsi";
  string mertric_str = (metric == 0) ? "inf" : std::to_string(metric);

  cout << std::format("[{}]  {:^5}  𝐿{}  {:^5}  {:^5}  "
                      "{:^10.3f}  {:^10.3f}",
                      pro_type, set_size, mertric_str, dim, delta, avg_com,
                      avg_online_time)
       << endl;

  return;
}

std::pair<double, double>
run_fpsi_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                  const u64 DELTA, const u64 INTERSECTION_SIZE, const string IP,
                  const u64 PORT, const bool FM_TYPE, const bool PTS_SAME,
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
    for (u64 i = 0; i < DIM; ++i) {
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

  // initialize parties
  FPSIRecv recv(DIM, DELTA, PT_NUM, METRIC, 1, recv_pts, fmap_recv, fmap_sender,
                socketPair0);
  FPSISender sender(DIM, DELTA, PT_NUM, METRIC, 1, send_pts, fmap_recv,
                    fmap_sender, socketPair1);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // PSI Offline phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto fpsi_offline = [&](FPSISender &s, FPSIRecv &r, bool fm_type, bool fake) {
    // figure 8 PSI offline phase
    if (fm_type) {
      std::thread recv_offline(std::bind(&FPSIRecv::psi_offline_fig8, &r));
      std::thread send_offline(std::bind(&FPSISender::psi_offline_fig8, &s));
      recv_offline.join();
      send_offline.join();
      return;
    }
    // figure 9 PSI offline phase
    if (fake) {
      s.psi_offline_fake();
      r.psi_offline_fake();
      return;
    } else {
      std::thread recv_offline(std::bind(&FPSIRecv::psi_offline, &r));
      std::thread send_offline(std::bind(&FPSISender::psi_offline, &s));
      recv_offline.join();
      send_offline.join();
      return;
    }
  };

  timer.start();
  fpsi_offline(sender, recv, FM_TYPE, FAKE);
  timer.end("protocol_offline");
  spdlog::info("PSI Offline phase finished !!");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // PSI Online phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  timer.start();
  if (FM_TYPE) {
    // figure 8 PSI online phase
    std::thread recv_msg(std::bind(&FPSIRecv::psi_online_fig8, &recv));
    std::thread send_msg(std::bind(&FPSISender::psi_online_fig8, &sender));
    recv_msg.join();
    send_msg.join();
  } else {
    // figure 9 PSI online phase
    std::thread recv_msg(std::bind(&FPSIRecv::psi_online, &recv));
    std::thread send_msg(std::bind(&FPSISender::psi_online, &sender));
    recv_msg.join();
    send_msg.join();
  }
  timer.end("protocol_online");
  spdlog::info("PSI Online phase finished !!");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Result statistics
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto offline_time = timer.get_by_key("protocol_offline");
  auto online_time = timer.get_by_key("protocol_online");

  auto total_com(0.0);
  for (u64 i = 0; i < DIM; i++) {
    total_com = total_com + socketPair0[i].bytesReceived() +
                socketPair1[i].bytesReceived();
  }

  spdlog::info("*********************** Result ****************************");
  spdlog::info("PSI intersection size      : {}",
               recv.intersection_idxs_tmp.size());
  // cout << "psi size: " << recv.intersection_idxs_tmp.size() << endl;

  spdlog::info("Offline time (s)           : {:.3f} ", offline_time / 1000.0);
  spdlog::info("Online time (s)            : {:.3f} ", online_time / 1000.0);
  spdlog::info("Total communication (MB)   : {:.3f} ",
               total_com / 1024.0 / 1024.0);

  spdlog::info("***********************************************************");
  if (DETAILED) {
    sender.print_commus();
    spdlog::info("***********************************************************");
    sender.print_time();
    spdlog::info("***********************************************************");
    recv.print_commus();
    spdlog::info("***********************************************************");
    recv.print_time();
    spdlog::info("***********************************************************");
  }

  return {online_time, total_com};
}

void run_fpsi_protocol_sh(const CLP &cmd) {
  string pro_type = "spatial_hash";

  // obtain protocol parameters
  const u64 num = cmd.getOr<u64>("n", 8);
  const u64 dim = cmd.getOr<u64>("d", 2);
  const u64 metric = cmd.getOr<u64>("m", 0);
  const u64 delta = cmd.getOr<u64>("delta", 10);
  const u64 intersection_size = cmd.getOr("i", 15);
  const u64 trait = cmd.getOr("trait", 1);
  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  const bool pts_same = cmd.isSet("same");
  const bool detailed = cmd.isSet("detail");
  const bool fake = cmd.isSet("fake");

  // check intersection size
  auto set_size = 1 << num;
  if (intersection_size > set_size) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  // obtain protocol parameters
  spdlog::info("*********************** setting ****************************");
  spdlog::info("set_size          : {}", set_size);
  spdlog::info("dimension         : {} ", dim);
  spdlog::info("metric            : l_{} ", metric);
  spdlog::info("delta             : {} ", delta);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("trait             : {}", trait);

  spdlog::info("fmap_type         : {}", pro_type);
  spdlog::info("pts_same          : {}", pts_same);
  spdlog::info("detailed          : {}", detailed);
  spdlog::info("fake              : {}", fake);
  spdlog::info("***********************************************************");

  vector<double> time_sums(trait, 0);
  vector<double> comm_sums(trait, 0.0);
  for (u64 i = 0; i < trait; i++) {
    std::pair<double, double> tmp =
        run_fpsi_protocol_sh(set_size, dim, metric, delta, intersection_size,
                             ip, port, pts_same, detailed, fake);
    time_sums[i] = tmp.first;
    comm_sums[i] = tmp.second;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / 1000.0 / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) /
                   1024.0 / 1024.0 / trait;

  string mertric_str = (metric == 0) ? "inf" : std::to_string(metric);

  cout << std::format("[{}]  {:^5}  𝐿{}  {:^5}  {:^5}  "
                      "{:^10.3f}  {:^10.3f}",
                      pro_type, set_size, mertric_str, dim, delta, avg_com,
                      avg_online_time)
       << endl;

  return;
}

std::pair<double, double>
run_fpsi_protocol_sh(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                     const u64 DELTA, const u64 INTERSECTION_SIZE,
                     const string IP, const u64 PORT, const bool PTS_SAME,
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
    for (u64 i = 0; i < DIM; ++i) {
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

  // initialize parties
  FPSIRecv recv(DIM, DELTA, PT_NUM, METRIC, 1, recv_pts, fmap_recv, fmap_sender,
                socketPair0);
  FPSISender sender(DIM, DELTA, PT_NUM, METRIC, 1, send_pts, fmap_recv,
                    fmap_sender, socketPair1);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // PSI Offline phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto fpsi_offline = [&](FPSISender &s, FPSIRecv &r, bool fake) {
    // figure 8 PSI offline phase
    std::thread recv_offline(std::bind(&FPSIRecv::psi_offline_sh, &r));
    std::thread send_offline(std::bind(&FPSISender::psi_offline_sh, &s));
    recv_offline.join();
    send_offline.join();
    return;
  };

  timer.start();
  fpsi_offline(sender, recv, FAKE);
  timer.end("protocol_offline");
  spdlog::info("PSI Offline phase finished !!");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // PSI Online phase
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  timer.start();

  // figure 8 PSI online phase
  std::thread recv_msg(std::bind(&FPSIRecv::psi_online_sh, &recv));
  std::thread send_msg(std::bind(&FPSISender::psi_online_sh, &sender));
  recv_msg.join();
  send_msg.join();

  timer.end("protocol_online");
  spdlog::info("PSI Online phase finished !!");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Result statistics
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto offline_time = timer.get_by_key("protocol_offline");
  auto online_time = timer.get_by_key("protocol_online");

  auto total_com(0.0);
  for (u64 i = 0; i < DIM; i++) {
    total_com = total_com + socketPair0[i].bytesReceived() +
                socketPair1[i].bytesReceived();
  }

  spdlog::info("*********************** Result ****************************");
  spdlog::info("PSI intersection size      : {}",
               recv.intersection_idxs_tmp.size());
  // cout << "psi size: " << recv.intersection_idxs_tmp.size() << endl;

  spdlog::info("Offline time (s)           : {:.3f} ", offline_time / 1000.0);
  spdlog::info("Online time (s)            : {:.3f} ", online_time / 1000.0);
  spdlog::info("Total communication (MB)   : {:.3f} ",
               total_com / 1024.0 / 1024.0);

  spdlog::info("***********************************************************");
  if (DETAILED) {
    sender.print_commus();
    spdlog::info("***********************************************************");
    sender.print_time();
    spdlog::info("***********************************************************");
    recv.print_commus();
    spdlog::info("***********************************************************");
    recv.print_time();
    spdlog::info("***********************************************************");
  }

  return {online_time, total_com};
}
