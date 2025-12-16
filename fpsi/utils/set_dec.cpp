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

/*
 Get the character at index n of a string (0-based)
*/
string get_char_at_index(const string &s, u64 index) {
  if (index < s.size()) {
    return string(1, s[index]);
  }
  return ""; // if index is out of range, return empty string
}

/*
Get the number of common prefix bits between two strings
*/
u64 common_prefix_length(const string &s1, const string &s2) {
  u64 length = 0;
  u64 min_length = min(s1.size(), s2.size());

  for (u64 i = 0; i < min_length; ++i) {
    if (s1[i] == s2[i]) {
      ++length;
    } else {
      break;
    }
  }

  return length;
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

// Trie structure definition
struct TrieNode {
  unique_ptr<TrieNode> children[2]; // left and right children
  string value;                     // leaf node value

  TrieNode(string val = "") : value(std::move(val)) {}

  // Initialize the tree with default bit length
  u64 initialize_default(u64 x, u64 y) { return initialize(x, y, NUM_BITS); }

  // Construct a binary Trie tree based on the interval [x, y]
  u64 initialize(u64 x, u64 y, u64 bits) {
    if (x > y) {
      cerr << "Error: x must be less than or equal to y" << endl;
      return 0;
    }
    if (x == y) {
      cerr << "Warning: x equal to y" << endl;
      value = to_binary_string(x, bits);
      return 0;
    }

    string left = to_binary_string(x, bits);
    string right = to_binary_string(y, bits);

    u64 common_length = common_prefix_length(left, right);
    u64 tree_levels = bits - common_length;

    value = get_first_n_chars(left, bits - tree_levels);
    fill_tree(tree_levels, 0);
    tail_tree(left, right, tree_levels, 0, common_length);

    return tree_levels;
  }

  // Fill the Trie tree to make it a complete binary tree
  void fill_tree(u64 height, u64 level) {
    if (level < height) {
      children[0] = make_unique<TrieNode>("0");
      children[1] = make_unique<TrieNode>("1");

      children[0]->fill_tree(height, level + 1);
      children[1]->fill_tree(height, level + 1);
    }
  }

  // Tailor the Trie tree based on the interval boundaries
  void tail_tree(const string &left, const string &right, u64 height, u64 level,
                 u64 index) {
    tail_tree_left(left, height, level, index);
    tail_tree_right(right, height, level, index);
  }

  void tail_tree_left(const string &left, u64 height, u64 level, u64 index) {
    string next_value = get_char_at_index(left, index);

    if (level < height) {
      if (next_value == "0") {
        if (children[0]) {
          children[0]->tail_tree_left(left, height, level + 1, index + 1);
        }
      } else if (next_value == "1") {
        children[0].reset();
        if (children[1]) {
          children[1]->tail_tree_left(left, height, level + 1, index + 1);
        }
      }
    }
  }

  void tail_tree_right(const string &right, u64 height, u64 level, u64 index) {
    string next_value = get_char_at_index(right, index);

    if (level < height) {
      if (next_value == "0") {
        children[1].reset();
        if (children[0]) {
          children[0]->tail_tree_right(right, height, level + 1, index + 1);
        }
      } else if (next_value == "1") {
        if (children[1]) {
          children[1]->tail_tree_right(right, height, level + 1, index + 1);
        }
      }
    }
  }

  // Get all maximal enclosing complete subtries
  vector<string> get_maximal_enclosing_complete_subtries(u64 tree_levels) {
    vector<string> subtries;
    collect_maximal_subtries(subtries, tree_levels, 0, value);
    return subtries;
  }

  void collect_maximal_subtries(vector<string> &subtries, u64 height, u64 level,
                                const string &prefix) {
    if (is_complete_binary_tree(height, level)) {
      subtries.push_back(prefix);
      return;
    }

    for (const auto &child : children) {
      if (child) {
        child->collect_maximal_subtries(subtries, height, level + 1,
                                        prefix + child->value);
      }
    }
  }

  bool is_complete_binary_tree(u64 height, u64 level) {
    if (level == height) {
      return true;
    }

    bool left_complete =
        children[0] && children[0]->is_complete_binary_tree(height, level + 1);
    bool right_complete =
        children[1] && children[1]->is_complete_binary_tree(height, level + 1);

    return left_complete && right_complete;
  }

  // Print the Trie tree
  void print_tree(u64 depth = 0) {
    cout << string(depth * 2, ' ') << "Value: " << value << endl;
    for (const auto &child : children) {
      if (child) {
        child->print_tree(depth + 1);
      }
    }
  }
};
} // namespace

/// Pad with 1s at the lower bits
u64 up_bound(const string &prefix) {
  string temp_str = prefix;
  temp_str.append(NUM_BITS - prefix.length(), '1');
  return bitset<NUM_BITS>(temp_str).to_ullong();
}

/// Pad with 0s at the lower bits
u64 low_bound(const string &prefix) {
  string temp_str = prefix;
  temp_str.append(NUM_BITS - prefix.length(), '0');
  return bitset<NUM_BITS>(temp_str).to_ullong();
}

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

vector<string> prefix(u64 value, u64 u) {
  string value_str = to_binary_string(value, NUM_BITS);
  vector<string> prefixes;

  while (u < 0) {
    prefixes.push_back(get_first_n_chars(value_str, NUM_BITS - u));
    u--;
  }

  return prefixes;
}