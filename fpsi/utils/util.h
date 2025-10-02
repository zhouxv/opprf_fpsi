#pragma once

#include <vector>

#include <blake3.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <spdlog/spdlog.h>

#include "config.h"
#include "utils/params_selects.h"

// simle timer
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
    std::lock_guard<std::mutex> lock(mtx);
    std::lock_guard<std::mutex> other_lock(other.mtx);

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

// Sampling with specified intersection size
void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts);

// Helper functions required for spatial hashing
pt cell(const pt &p, u64 dim, u64 side_len);
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen);

u64 l1_dist(const pt &p1, const pt &p2, u64 dim);
u64 l2_dist(const pt &p1, const pt &p2, u64 dim);
u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim);

u64 get_position(const pt &cross_point, const pt &source_point, u64 dim);
vector<pt> intersection(const pt &p, u64 metric, u64 dim, u64 delta,
                        u64 sidelen, u64 blk_cells, u64 delta_l2);

vector<u64> sum_combinations(const oc::span<u32> &results, u64 dim);
u64 fast_pow(u64 base, u64 exp);
u64 combination(u64 n, u64 k);

const PrefixParam get_omega_params(u64 metric, u64 delta, u64 dim);

const PrefixParam get_if_match_params(u64 metric, u64 delta);

const PrefixParam get_fuzzy_mapping_params(u64 metric, u64 delta);

inline void padding_vec_8(vector<u64> &vec) {
  auto size = vec.size();
  auto remainder = size % 8;
  if (remainder != 0) {
    auto padding_num = 8 - remainder;
    for (u64 i = 0; i < padding_num; i++) {
      vec.push_back(0);
    }
  }
}

struct Monty25519Hash {
  std::size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    std::array<u8, 32> bytes;
    point.toBytes(bytes.data()); // Assuming Monty25519 provides toBytes method
    return std::hash<std::string_view>()(
        std::string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};

// delta internal Align Top
u64 align_to_interval(u64 value);