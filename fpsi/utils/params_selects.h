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

class DFmapParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    call_once(flag, []() {
      params[21] = {{0, 1, 2, 3, 4}, 6};

      params[61] = {{0, 1, 2, 3, 4, 5}, 9};

      params[121] = {{0, 1, 2, 3, 4, 5, 6}, 10};

      params[241] = {{0, 1, 2, 3, 4, 5, 6, 7}, 12};

      params[501] = {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 14};
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