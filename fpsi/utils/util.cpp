#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>

#include "utils/util.h"

void sample_points(u64 dim, u64 delta, u64 send_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &send_pts,
                   vector<pt> &recv_pts, bool same) {
  PRNG prng(oc::sysRandomSeed());

  for (u64 i = 0; i < send_size; i++) {
    for (u64 j = 0; j < dim; j++) {
      send_pts[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
          1.5 * delta;
    }
  }

  if (same) {
    for (u64 i = 0; i < recv_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        recv_pts[i][j] = send_pts[i][j];
      }
    }
  } else {
    for (u64 i = 0; i < recv_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        recv_pts[i][j] =
            (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
            1.5 * delta;
      }
    }

    // u64 base_pos = (prng.get<u64>()) % (send_size - intersection_size - 1);
    u64 base_pos = 0;
    for (u64 i = base_pos; i < base_pos + intersection_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        send_pts[i][j] = recv_pts[i - base_pos][j];
      }
      for (u64 j = 0; j < 1; j++) {
        send_pts[i][j] += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
      }
    }
  }
}

/// Calculate the cell coordinates of point p in a grid with side length sidele.
/// This function divides each coordinate of point p by sidele to get its cell
/// coordinates in the grid.
///
/// # Parameters
/// - `p`: A reference to a Point type, representing the coordinates of the
/// point.
/// - `sidele`: A value of type u64, representing the side length of the grid.
///
/// # Returns
/// Returns a Point type value, representing the cell coordinates of point p in
/// the grid.
pt cell(const pt &p, u64 dim, u64 side_len) {
  pt bot_left_corner(dim, 0); // initialize to 0
  for (u64 i = 0; i < dim; ++i) {
    bot_left_corner[i] = p[i] / side_len; // compute cell coordinate
  }
  return bot_left_corner;
}

/// Calculate the boundary cell coordinates of a region based on point p, grid
/// side length sidele, and radius. This function first subtracts the radius
/// from each coordinate of point p, then calls the cell function to compute the
/// cell coordinates of the boundary block.
///
/// # Parameters
/// - `p`: A reference to a Point type, representing the coordinates of the
/// point.
/// - `sidele`: A value of type u64, representing the side length of the grid.
/// - `radius`: A value of type u64, representing the radius of the region.
///
/// # Returns
/// Returns a Point type value, representing the boundary cell coordinates of
/// the region.
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen) {
  pt min(dim, 0); // initialize to 0
  for (u64 i = 0; i < dim; ++i) {
    // compute the coordinate of point p in a certain dimension i minus a radius
    // value
    min[i] = p[i] - delta;
  }
  return cell(min, dim,
              sidelen); // compute the cell coordinates of the boundary block
}

/// Calculate the L1 distance between two points p1 and p2.
/// This function computes the sum of the absolute differences of the
/// coordinates of the two points in each dimension.
///
/// # Parameters
/// - `p1`: A reference to a pt type, representing the coordinates of the first
/// point.
/// - `p2`: A reference to a pt type, representing the coordinates of the second
/// point.
///
/// # Returns
/// Returns a value of type u64, representing the L1 distance between the two
/// points.
u64 l1_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 sum = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    sum += diff;
  }
  return sum;
}

/// Calculate the squared L2 distance between two points p1 and p2.
/// This function computes the sum of the squares of the differences of the
/// coordinates of the two points in each dimension.
///
/// # Parameters
/// - `p1`: A reference to a pt type, representing the coordinates of the first
/// point.
/// - `p2`: A reference to a pt type, representing the coordinates of the second
/// point.
/// - `dim`: The number of dimensions.
///
/// # Returns
/// Returns a value of type u64, representing the squared L2 distance between
/// the two points.
u64 l2_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 sum = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    sum += diff * diff;
  }
  return sum;
}

/// Calculate the L∞ distance between two points p1 and p2.
/// This function computes the absolute difference of the coordinates of the two
/// points in each dimension, then takes the maximum value.
///
/// # Parameters
/// - `p1`: A reference to a pt type, representing the coordinates of the first
/// point.
/// - `p2`: A reference to a pt type, representing the coordinates of the second
/// point.
///
/// # Returns
/// Returns a value of type u64, representing the L∞ distance between the two
/// points.
u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 max_diff = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    max_diff = max(max_diff, diff);
  }
  return max_diff;
}

/// Calculate the position index of point p relative to the source point.
/// This function determines the position of point p relative to the source
/// point by comparing each coordinate of p and the source point.
///
/// # Parameters
/// - `cross_point`: A reference to a Point type, representing the coordinates
/// of the point.
/// - `source_point`: A reference to a Point type, representing the coordinates
/// of the source point.
///
/// # Returns
/// Returns a value of type usize, representing the position index of point p
/// relative to the source point.
u64 get_position(const pt &cross_point, const pt &source_point, u64 dim) {
  u64 pos = 0;
  for (u64 i = 0; i < dim; ++i) {
    if (cross_point[i] > source_point[i]) {
      pos += 1ULL << i;
    }
  }
  return pos;
}

/// Calculate the intersection region of point p based on the metric.
/// This function first computes the block where point p is located, then
/// calculates the boundary of the intersection region according to the metric.
/// For L1 and L2 metrics, the function computes the boundary blocks of the
/// intersection region and adds them to the result vector.
///
/// # Parameters
/// - `p`: A reference to a Point type, representing the coordinates of the
/// point.
/// - `metric`: A value of type usize, representing the metric type (1 for L1, 2
/// for L2).
///
/// # Returns
/// Returns a vector of Point type, containing the boundary block coordinates of
/// the intersection region.
vector<pt> intersection(const pt &p, u64 metric, u64 dim, u64 delta,
                        u64 sidelen, u64 blk_cells, u64 delta_l2) {
  // initial result vector
  vector<pt> results;
  results.reserve(blk_cells);

  // compute the bottom-left corner coordinates of the block where point p is
  // located
  pt blk = block_(p, dim, delta, sidelen);
  pt cross_point(dim, 0);

  // compute the coordinates of the cross point, which is the top-right
  for (u64 i = 0; i < dim; ++i) {
    cross_point[i] = blk[i] * sidelen + sidelen;
  }

  u64 dist;
  // compute the distance based on the metric
  if (metric == 2) {
    dist = l2_dist(p, cross_point, dim);
  } else if (metric == 1) {
    dist = l1_dist(p, cross_point, dim);
  } else if (metric == 0) {
    dist = l_inf_dist(p, cross_point, dim);
  } else {
    throw invalid_argument("Invalid metric value.");
  }

  // get the position index of the cross point relative to the source point p
  u64 pos_ind = get_position(cross_point, p, dim);

  // traverse all boundary blocks
  for (u64 i = 0; i < blk_cells; ++i) {
    pt temp(dim, 0);
    // determine the r_lp based on the metric
    u64 r_lp = (metric == 2) ? delta_l2 : delta;

    // if the distance is greater than the radius and the current block is the
    // position of the cross point, skip it
    if (dist > r_lp && i == pos_ind) {
      continue;
    }

    // compute the coordinates of the current block
    for (u64 j = 0; j < dim; ++j) {
      if ((i >> j) & 1) {
        // (i >> j) & 1 is used to get the j-th bit of i
        temp[j] = blk[j] + 1;
      } else {
        temp[j] = blk[j];
      }
    }
    // add the coordinates of the current block to the results
    results.push_back(temp);
  }

  return results;
}

/// Calculate the combination number
///
/// Calculate the number of combinations for choosing `k` elements from `n`
/// elements.
///
/// # Parameters
/// - `n`: Total number of elements
/// - `k`: Number of elements to choose
///
/// # Returns
/// Returns a value of type `u64` representing the number of combinations.
/// Returns 0 if `k` is greater than `n`.
u64 combination(u64 n, u64 k) {
  if (k > n)
    return 0;
  if (k > n - k)
    k = n - k; // C(n, k) == C(n, n-k), do less computation
  u64 result = 1;
  for (u64 i = 0; i < k; ++i) {
    result = result * (n - i) / (i + 1);
  }
  return result;
}

// fast exponentiation
u64 fast_pow(u64 base, u64 exp) {
  u64 result = 1;
  while (exp > 0) {
    if (exp & 1)
      result *= base;
    base *= base;
    exp >>= 1;
  }
  return result;
}

// Optimized version using sorting (your approach)
vector<u64> get_phi_dim_optimized(const vector<pt> &pts, u64 delta) {
  auto pt_num = pts.size();
  u64 dim = pts[0].size();
  vector<u64> common_phi_dims;

  // Iterate through each dimension
  for (u64 d = 0; d < dim; ++d) {
    // Extract and sort all coordinates in this dimension
    vector<pair<u64, u64>> intervals; // store (coordinate, original_index)
    for (u64 i = 0; i < pt_num; ++i) {
      intervals.push_back({pts[i][d], i});
    }

    // Sort by coordinate
    sort(intervals.begin(), intervals.end());

    bool dimension_is_valid = true;

    // Check adjacent intervals for overlap
    for (u64 i = 0; i < intervals.size() - 1; ++i) {
      u64 current_upper = intervals[i].first + delta;
      u64 next_lower = intervals[i + 1].first - delta;

      // If intervals overlap, this dimension cannot be phi for all points
      if (current_upper >= next_lower) {
        dimension_is_valid = false;
        break;
      }
    }

    if (dimension_is_valid) {
      common_phi_dims.push_back(d);
      // break;
    }
  }

  return common_phi_dims;
}

vector<block> bignumer_to_block_vector(const BigNumber &bn) {
  vector<u32> ct;
  bn.num2vec(ct);

  vector<block> cipher_block(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock);

  PRNG prng(oc::sysRandomSeed());

  if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] = prng.get<block>();
    }
  } else {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] =
          block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i])));
    }
  }

  return cipher_block;
}

BigNumber block_vector_to_bignumer(const std::vector<block> &ct) {
  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);
  u32 temp[4];
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    memcpy(temp, ct[i].data(), 16);

    ct_u32[4 * i] = temp[0];
    ct_u32[4 * i + 1] = temp[1];
    ct_u32[4 * i + 2] = temp[2];
    ct_u32[4 * i + 3] = temp[3];
  }
  BigNumber bn = BigNumber(ct_u32.data(), ct_u32.size());
  return bn;
}

vector<block> flattenBlocks(const vector<vector<block>> &blockData) {
  // 首先计算总元素数量
  size_t total_size = 0;
  for (const auto &inner_vec : blockData) {
    total_size += inner_vec.size();
  }

  // 预分配足够的内存
  vector<block> result;
  result.reserve(total_size);

  // 逐个向量进行内存拷贝
  for (const auto &inner_vec : blockData) {
    if (!inner_vec.empty()) {
      // 直接使用内存拷贝，避免逐个push_back
      size_t old_size = result.size();
      result.resize(old_size + inner_vec.size());
      memcpy(result.data() + old_size, inner_vec.data(),
             inner_vec.size() * sizeof(block));
    }
  }

  return result;
}

vector<vector<block>> chunkFixedSizeBlocks(const vector<block> &flatData,
                                           size_t chunk_size) {
  assert(chunk_size > 0 && "Chunk size must be positive");
  assert(flatData.size() % chunk_size == 0 &&
         "Data size must be divisible by chunk size");

  vector<vector<block>> result;
  result.reserve(flatData.size() / chunk_size);

  for (size_t i = 0; i < flatData.size(); i += chunk_size) {
    result.emplace_back(flatData.begin() + i,
                        flatData.begin() + i + chunk_size);
  }

  return result;
}
