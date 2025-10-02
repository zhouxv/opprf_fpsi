#pragma once
#include <cryptoTools/Common/Defines.h>
#include <format>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

using namespace std;
using namespace oc;

using PrefixParam = std::pair<std::set<u64>, u64>;

class OmegaLowTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[17] = {{0, 1, 2, 3}, 5};

      params[33] = {{0, 1, 2, 3, 4}, 6};

      params[65] = {{0, 1, 2, 3, 4, 5}, 7};

      params[129] = {{0, 1, 2, 3, 4, 5, 6}, 8};

      params[257] = {{0, 1, 2, 3, 4, 5, 6, 7}, 9};

      params[513] = {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

class OmegaHighLinfTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[33] = {{0, 2}, 12};

      params[65] = {{0, 3}, 16};

      params[129] = {{0, 1, 3, 5}, 11};

      params[257] = {{0, 2, 4, 6}, 14};

      params[513] = {{0, 2, 4, 6}, 18};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

class OmegaHighLpTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[17] = {{0, 2}, 8};

      params[33] = {{0, 2}, 12};

      params[65] = {{0, 1, 3, 4}, 9};

      params[129] = {{0, 1, 3, 5}, 11};

      params[257] = {{0, 2, 4, 6}, 14};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

class IfMatchParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    // ifmatch uses parameter settings from unused set_dec
    call_once(flag, []() {
      params[17] = {{0, 2}, 8};
      params[33] = {{0, 2}, 12};
      params[65] = {{0, 3}, 16};
      params[129] = {{0, 3}, 24};
      params[257] = {{0, 4}, 32};
      params[1025] = {{0, 5}, 64};
      params[4097] = {{0, 6}, 128};
      params[16385] = {{0, 7}, 256};
      params[65537] = {{0, 8}, 1024};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range(std::format(
        "IfMatchParamTable getSelectedParam Invalid parameter key: {}", t));
  }
};

class FuzzyMappingParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[17] = {{0, 1, 2, 3}, 5};

      params[33] = {{0, 1, 2, 3, 4}, 6};

      params[65] = {{0, 1, 2, 3, 4, 5}, 7};

      params[129] = {{0, 1, 2, 3, 4, 5, 6}, 8};

      params[257] = {{0, 1, 2, 3, 4, 5, 6, 7}, 9};

      params[513] = {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

inline string pairToString(const PrefixParam &p) {
  ostringstream oss;
  oss << "{ {";

  for (auto it = p.first.begin(); it != p.first.end(); ++it) {
    if (it != p.first.begin())
      oss << ", ";
    oss << *it;
  }

  oss << "}, " << p.second << " }";
  return oss.str();
}