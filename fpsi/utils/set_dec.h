#pragma once
#include "config.h"
#include <set>
#include <string>
#include <vector>

u64 up_bound(const std::string &prefix);
u64 low_bound(const std::string &prefix);

vector<string> decompose(u64 x, u64 y);
vector<string> decompose_improve(u64 x, u64 y);

vector<string> set_dec(u64 x, u64 y, const set<u64> &u);
vector<string> set_dec_improve(u64 x, u64 y, const set<u64> &u);
vector<string> set_prefix(u64 value, const set<u64> &u_set);
