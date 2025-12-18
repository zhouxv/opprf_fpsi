#pragma once
#include "config.h"
#include "utils/simpleTimer.h"
#include "utils/util.h"

#include <coproto/Socket/Socket.h>
#include <vector>

class FPSIBase {
public:
  explicit FPSIBase(vector<coproto::Socket> &sockets) : sockets(sockets) {}

  /*
  Counter of Communication and Time
  */
  simpleTimer fpsi_timer;                        // timer
  std::vector<std::pair<string, double>> commus; // communication counter
  vector<coproto::Socket> &sockets;              // communication socket

  void print_time() { fpsi_timer.print(); }

  void merge_timer(simpleTimer &other) { fpsi_timer.merge(other); }

  void print_commus() {
    for (auto &x : commus) {
      spdlog::info("{}: {} MB", x.first, x.second / 1024.0 / 1024.0);
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back({msg, sockets[socket_index].bytesSent()});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }

  // required
  virtual ~FPSIBase() = default;
};