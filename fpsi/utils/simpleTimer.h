#pragma once
#include "config.h"

#include <map>
#include <spdlog/spdlog.h>

typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

class simpleTimer {
public:
  std::mutex mtx;
  tVar t;
  std::map<string, double> timers;
  std::vector<string> timer_keys;

  simpleTimer() {}

  void start() { tStart(t); }
  void end(string msg) {
    timer_keys.push_back(msg);
    timers[msg] = tEnd(t);
  }

  void print() {
    for (const string &key : timer_keys) {
      spdlog::info("{}: {} ms; {} s", key, timers[key], timers[key] / 1000);
    }
  }

  double get_by_key(const string &key) { return timers.at(key); }

  void merge(simpleTimer &other) {
    if (&other == this)
      return;
    std::lock_guard<std::mutex> lock(mtx);

    auto other_keys = other.timer_keys;
    auto other_maps = other.timers;

    timer_keys.insert(timer_keys.end(), other_keys.begin(), other_keys.end());
    timers.insert(other_maps.begin(), other_maps.end());
  }

  void clear() {
    timers.clear();
    timer_keys.clear();
  }
};