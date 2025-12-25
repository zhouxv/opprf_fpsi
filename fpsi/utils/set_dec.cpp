#include "set_dec.h"
#include <bitset>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>

const u64 NUM_BITS = 64;

// Some methods used only in this file
namespace {

/*
Convert u64 to a binary string with leading zeros, length is bits
*/
string to_binary_string(u64 value, u64 bits) {
  return bitset<NUM_BITS>(value).to_string().substr(0, bits);
}

/*
Get the first n characters of a string
*/
string get_first_n_chars(const string &s, u64 n) {
  if (n > s.size()) {
    throw out_of_range("get_first_n_chars: n > s.size()");
  }
  return s.substr(0, n);
}

// Find the largest value in `u_set` that is less than `dec`
u64 set_round(u64 dec, const set<u64> &u_set) {
  if (u_set.empty()) {
    throw runtime_error("set_round panic! The set is empty.");
  }

  auto it = u_set.lower_bound(dec); // find the first element not less than dec

  if (it == u_set.begin()) {
    // No element is less than dec, return 0 or other appropriate value
    return 0;
  }

  --it; // Move to the largest element less than dec
  return *it;
}
} // namespace

// Decompose the interval [min, max] using an improved method in appendix
vector<string> decompose_improve(u64 min, u64 max) {
  if (min > max) {
    throw runtime_error("decompose improve: max should >= min");
  }

  if (min == max) {
    return {to_binary_string(min, NUM_BITS)};
  }

  u64 t = max - min + 1; // intervals length
  u64 w = static_cast<u64>(std::log2(t)) + 1;
  u64 a_prime = min;

  // step 1
  // find a_prime >= a, s.t. 2^(w-1) | a_prime
  while (a_prime <= max && (a_prime & ((1 << (w - 1)) - 1))) {
    a_prime++;
  }

  if (a_prime > max) {
    throw runtime_error("decompose improve: can't find a_prime");
  }

  // step 2
  // x = a+t-a'; y=a'-a
  u64 x = max - a_prime + 1; // right side length
  u64 y = a_prime - min;     // left side length

  // convert to binary representation, bitset access is from low bit to high bit
  std::bitset<NUM_BITS> x_binary(x);
  std::bitset<NUM_BITS> y_binary(y);

  std::vector<std::string> P; // result set
  u64 x_prime = a_prime;      // move right
  u64 y_prime = a_prime - 1;  // move left

  // traverse from high bit to low bit
  for (u64 i = w; i >= 1; i--) {
    auto bits = NUM_BITS - i + 1;
    if (x_binary[i - 1]) {
      // if x's i-th bit is 1
      P.push_back(to_binary_string(x_prime, bits));
      x_prime += (1 << (i - 1));
    }
    if (y_binary[i - 1]) {
      // if y's i-th bit is 1
      P.push_back(to_binary_string(y_prime, bits));
      y_prime -= (1 << (i - 1));
    }
  }

  return P;
}

// set_dec function
// Decompose the interval [x, y] and adjust according to the set u
vector<string> set_dec(u64 x, u64 y, const set<u64> &u) {
  vector<string> decs = decompose_improve(x, y);
  vector<string> res_decs;

  for (const auto &dec : decs) {
    u64 len = dec.length();
    u64 mu = NUM_BITS - len;

    if (u.count(mu)) {
      res_decs.push_back(dec);
      continue;
    }

    u64 mu_star = set_round(mu, u);

    u64 padding_bits = mu - mu_star;
    u64 str_count = 1ULL << padding_bits;

    string binary;
    binary.reserve(padding_bits);

    for (u64 i = 0; i < str_count; ++i) {
      binary.clear();
      for (u64 j = 0; j < padding_bits; ++j) {
        binary.push_back((i >> j) & 1 ? '1' : '0');
      }
      res_decs.push_back(dec + binary);
    }
  }

  return res_decs;
}

// compute the prefix set
// for a given value, compute the prefixes based on the set u
vector<string> set_prefix(u64 value, const set<u64> &u_set) {
  string value_str = to_binary_string(value, NUM_BITS);
  vector<string> prefixes;

  for (u64 i : u_set) {
    prefixes.push_back(get_first_n_chars(value_str, NUM_BITS - i));
  }

  return prefixes;
}
