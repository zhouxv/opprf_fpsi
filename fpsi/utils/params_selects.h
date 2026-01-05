#pragma once
#include <cryptoTools/Common/Defines.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>

using namespace std;
using namespace oc;

using PrefixParam = std::pair<std::set<u64>, u64>;

class LpParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[10] = {{0, 1}, 6};
      params[11] = {{0, 2}, 5};
      params[30] = {{0, 1, 2, 3}, 8};
      params[31] = {{0, 1, 2, 3}, 6};
      params[60] = {{0, 2, 3, 4}, 10};
      params[61] = {{0, 2, 3, 4}, 11};
      params[120] = {{0, 3, 4, 5}, 14};
      params[121] = {{0, 2, 4, 5}, 14};
      params[250] = {{0, 2, 4, 6}, 19};
      params[251] = {{0, 2, 4, 6}, 17};

      // params[30] = {{0, 2}, 12};
      // params[31] = {{0, 2}, 10};
      // params[60] = {{0, 3}, 18};
      // params[61] = {{0, 3}, 19};
      // params[120] = {{0, 3}, 22};
      // params[121] = {{0, 3}, 23};
      // params[250] = {{0, 3}, 40};
      // params[251] = {{0, 3}, 31};
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

class LinfParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      // 𝑡=2𝛿+1
      params[21] = {{0, 1, 2, 3}, 6};

      params[61] = {{0, 1, 2, 3, 4}, 9};

      params[121] = {{0, 1, 2, 3, 4, 5}, 10};

      params[241] = {{0, 1, 2, 3, 5, 6}, 13};

      params[501] = {{0, 1, 2, 4, 5, 6}, 17};
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