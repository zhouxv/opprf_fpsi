#include "fpsi_recv.h"
#include "opprf/Opprf.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/simpleTimer.h"
#include "utils/util.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>

void FPSIRecv::DFmap_fig8_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = PrefixParamTable::getSelectedParam(t);

  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  // Generate r_x_i
  r_x_i.resize(PTS_NUM * DIM);
  recv_prng.get(r_x_i.data(), PTS_NUM * DIM);
  fig8_ID_xr = r_x_i;

  // Generate x_i_s
  vector<pair<u64, u64>> x_i_s(PTS_NUM * DIM);

  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {

      u64 temp0 = (pts[pt_idx][dim_idx] - SIDE_LEN) / SIDE_LEN;
      u64 temp1 = pts[pt_idx][dim_idx] / SIDE_LEN;

      x_i_s[pt_idx * DIM + dim_idx] = make_pair(temp0, temp1);
    }
  }

  // Generate dfmap_opprf_keys and dfmap_opprf_values
  auto opprf_num = 4 * PTS_NUM * DIM;
  dfmap_opprf_keys.reserve(opprf_num);
  dfmap_opprf_values.reserve(opprf_num);

  // Generate dfmap_opprf_keys and dfmap_opprf_values
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      block keys[4];
      keys[0] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].first, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].first);
      keys[1] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].first, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].second);
      keys[2] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].second, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].first);
      keys[3] = get_fmap_opprf_key(φ, x_i_s[pt_idx * DIM + φ].second, dim_idx,
                                   x_i_s[pt_idx * DIM + dim_idx].second);

      unordered_set<block> seen_keys;
      for (int i = 0; i < 4; i++) {
        if (seen_keys.insert(keys[i]).second) {
          dfmap_opprf_keys.push_back(keys[i]);
          dfmap_opprf_values.push_back(r_x_i[pt_idx * DIM + dim_idx]);
        }
      }
    }
  }

  padding_blocks(dfmap_opprf_keys, opprf_num);
  padding_blocks(dfmap_opprf_values, opprf_num);

  spdlog::debug("[Recv  ] opprf_0_num: {}, dfmap_opprf_keys: {} ", opprf_num,
                dfmap_opprf_keys.size());
}

void FPSIRecv::DFmap_fig8_online() {
  u64 opprf_size = dfmap_opprf_keys.size();
  u64 opprf_size_other;
  coproto::sync_wait(sockets[0].send(opprf_size));
  coproto::sync_wait(sockets[0].recv(opprf_size_other));

  volePSI::RsOpprfSender sender;

  coproto::sync_wait(sender.send(opprf_size_other, dfmap_opprf_keys,
                                 dfmap_opprf_values, recv_prng, 1, sockets[0]));

  spdlog::debug("recv fig8 ids size: {}", fig8_ID_xr.size());
}

void FPSIRecv::getID() {
  vector<vector<pair<u64, u64>>> intervals(DIM); // intervals

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // computes random numbers
  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_values_bns(PTS_NUM * DIM, 0);

  auto bits_num = (DIM <= 1) ? 0 : std::bit_width(DIM - 1);
  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = recv_prng.get<u32>() >> bits_num;
    random_values_bns[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  ipcl::PlainText randoms_pt = ipcl::PlainText(random_values_bns);
  ipcl::CipherText random_ciphers = fmap_recv_key.pub_key.encrypt(randoms_pt);
  ipcl::terminateContext();

  spdlog::debug("recv getID() random numbers computed");

  // Merge interval
  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<pair<u64, u64>> interval;
    interval.reserve(PTS_NUM);

    // get interval [a_i - radius, a_i + radius]
    for (const auto &pt : pts) {
      interval.push_back(
          {(pt[dim_index] - SIDE_LEN) / SIDE_LEN, (pt[dim_index]) / SIDE_LEN});
    }

    // sort interval
    std::sort(interval.begin(), interval.end());

    // merge interval
    vector<pair<u64, u64>> merged_interval;
    if (!interval.empty()) {
      u64 current_start = interval[0].first;
      u64 current_end = interval[0].second;

      for (u64 i = 1; i < interval.size(); i++) {
        u64 next_start = interval[i].first;
        u64 next_end = interval[i].second;

        // check overlap
        if (next_start <= current_end) {
          // if overlap, extend the current interval's end if needed
          current_end = max(current_end, next_end);
        } else {
          // if no overlap, add the current interval to merged list
          merged_interval.push_back({current_start, current_end});
          current_start = next_start;
          current_end = next_end;
        }
      }

      // add the last interval
      merged_interval.push_back({current_start, current_end});
    }
    intervals[dim_index] = merged_interval;
  }

  spdlog::debug("getID() interval merge finished");

  // get idxs
  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value; // Find the first interval where second <= value
  };

  IDs.resize(PTS_NUM, 0);
  u64 pt_index = 0;

  for (const auto &point : pts) {
    for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
      u64 temp_blk = (point[dim_index]) / SIDE_LEN;
      auto it = std::lower_bound(intervals[dim_index].begin(),
                                 intervals[dim_index].end(), temp_blk,
                                 compare_lambda);

      if (it != intervals[dim_index].end() && it->first <= temp_blk) {
        auto j = distance(intervals[dim_index].begin(), it);
        IDs[pt_index] += random_values[dim_index * PTS_NUM + j];
      } else {
        throw runtime_error("getID random error");
      }
    }
    pt_index += 1;
  }

  spdlog::debug("getID() idx computation completed");

  // get list encoding
  u64 okvs_mN = PTS_NUM * DIM * 2;

  RBOKVS rb_okvs;
  rb_okvs.init(okvs_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  u64 okvs_mSize = rb_okvs.mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK;

  get_id_encoding =
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length));
  vector<block> get_id_keys;
  vector<vector<block>> get_id_values;
  get_id_keys.reserve(okvs_mN);
  get_id_values.reserve(okvs_mN);

  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    for (u64 interval_index = 0; interval_index < intervals[dim_index].size();
         interval_index++) {
      for (u64 start = intervals[dim_index][interval_index].first;
           start <= intervals[dim_index][interval_index].second; start++) {
        get_id_keys.push_back(get_fmap_okvs_key(dim_index, start));
        get_id_values.push_back(bignumer_to_block_vector(
            random_ciphers[dim_index * PTS_NUM + interval_index]));
      }
    }
  }
  padding_keys(get_id_keys, okvs_mN);
  padding_values(get_id_values, okvs_mN, value_block_length);

  rb_okvs.encode(get_id_keys, get_id_values, value_block_length,
                 get_id_encoding);

  spdlog::debug("getID() computation completed");
}

void FPSIRecv::DFmap_fig9_offline() {
  getID();
  spdlog::debug("[recv] getID finished");

  fm_mask.resize(PTS_NUM + 1, 0);
  vector<u64> fm_mask_mul0(PTS_NUM, 0);

  vector<BigNumber> fm_mask_mul0_bn(PTS_NUM);
  vector<BigNumber> IDs_bn(PTS_NUM);

  recv_prng.get(fm_mask.data(), fm_mask.size());
  for (auto &v : fm_mask) {
    v = v >> 2;
  }

  for (u64 i = 0; i < PTS_NUM; i++) {
    fm_mask_mul0[i] = (u64)fm_mask[i + 1] * (u64)fm_mask[0];
    fm_mask_mul0_bn[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&fm_mask_mul0[i]), 2);
    IDs_bn[i] = BigNumber(reinterpret_cast<Ipp32u *>(&IDs[i]), 2);
  }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  mask_mul0_pt = ipcl::PlainText(fm_mask_mul0_bn);
  IDs_ct = fmap_sender_key.pub_key.encrypt(ipcl::PlainText(IDs_bn));

  ipcl::terminateContext();
}

void FPSIRecv::DFmap_fig9_online() {
  simpleTimer fm_timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send getID encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto get_id_mN = PTS_NUM * DIM * 2;
  auto get_id_mSize = get_id_encoding.size();

  coproto::sync_wait(sockets[0].send(get_id_mN));
  coproto::sync_wait(sockets[0].send(get_id_mSize));

  coproto::sync_wait(sockets[0].send(flattenBlocks(get_id_encoding)));

  insert_commus("recv_fm_get_id_encodings", 0);
  coproto::sync_wait(sockets[0].flush());
  spdlog::debug("[recv] getID encodings sent finished");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // receive send_get_id_encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 get_id_value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK;

  vector<block> flatten_get_id_encodings(get_id_mSize *
                                         get_id_value_block_length);

  coproto::sync_wait(sockets[0].recvResize(flatten_get_id_encodings));

  auto send_encoding =
      chunkFixedSizeBlocks(flatten_get_id_encodings, get_id_value_block_length);

  spdlog::debug("[send] received get_id_encodings");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // decode send_encoding
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  RBOKVS rbokvs;
  rbokvs.init(get_id_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<vector<BigNumber>> decoded_bns(DIM);

  for (u64 i = 0; i < pts.size(); i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto decode = rbokvs.decode(
          send_encoding, get_fmap_okvs_key(j, (pts[i][j] - DELTA) / SIDE_LEN),
          get_id_value_block_length);
      decoded_bns[j].push_back(block_vector_to_bignumer(decode));
    }
  }

  spdlog::debug("[recv] send_encoding decoded finished");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // homomorphic addition
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::CipherText v_add_res;
  for (u64 i = 0; i < DIM; i++) {
    auto temp = ipcl::CipherText(fmap_sender_key.pub_key, decoded_bns[i]);
    if (i == 0) {
      v_add_res = temp;
    } else {
      v_add_res = v_add_res + temp;
    }
  }
  spdlog::debug("[recv] homomorphic addition finished");

  ipcl::terminateContext();

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step6 compute u
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  auto u_cts = (v_add_res + IDs_ct) * mask_mul0_pt;
  // auto tmp_add = v_add_res + IDs_ct;
  // auto add_dec = fmap_sender_key.priv_key.decrypt(tmp_add);
  // auto u_dec = fmap_sender_key.priv_key.decrypt(u_cts);
  // for (u64 i = 0; i < 10; i++) {
  //   auto tmp = add_dec.getElementVec(i);
  //   u64 tmp_ = ((u64)tmp[1] << 32) | tmp[0];
  //   auto tmp2 = u_dec.getElementVec(i);
  //   u128 tmp2_ = ((u128)tmp2[3] << 96) | ((u128)tmp2[2] << 64) |
  //                ((u128)tmp2[1] << 32) | tmp2[0];
  //   cout << fmt::format("[recv] IDs2 [{}] {} {} {} {} {} {}", i, tmp_,
  //                       fm_mask[0], fm_mask[i + 1],
  //                       (u64)fm_mask[0] * (u64)fm_mask[i + 1],
  //                       (u128)fm_mask[0] * (u128)fm_mask[i + 1] * tmp_,
  //                       tmp2_)
  //        << endl;
  // }

  spdlog::debug("[recv] compute u finished");

  vector<vector<block>> u_cts_blks(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    u_cts_blks[i] = bignumer_to_block_vector(u_cts[i]);
  }

  coproto::sync_wait(sockets[0].send(flattenBlocks(u_cts_blks)));
  insert_commus("recv_fm_u_cts", 0);
  coproto::sync_wait(sockets[0].flush());
  spdlog::debug("[recv] u_cts sent finished");

  vector<block> send_u_cts_flat(PTS_NUM * PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(send_u_cts_flat));

  auto send_u_cts =
      chunkFixedSizeBlocks(send_u_cts_flat, PAILLIER_CIPHER_SIZE_IN_BLOCK);

  vector<BigNumber> send_u_cts_bn(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    send_u_cts_bn[i] = block_vector_to_bignumer(send_u_cts[i]);
  }

  auto w_pt = fmap_recv_key.priv_key.decrypt(
      ipcl::CipherText(fmap_recv_key.pub_key, send_u_cts_bn));
  spdlog::debug("[recv] decrypt w finished");

  vector<u128> w_mul_mask(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    auto tmp = w_pt.getElementVec(i);
    w_mul_mask[i] = ((u128)tmp[3] << 96) | ((u128)tmp[2] << 64) |
                    ((u128)tmp[1] << 32) | tmp[0];
    w_mul_mask[i] = w_mul_mask[i] * (u128)fm_mask[0];
  }

  vector<u128> send_w_mul_mask(PTS_NUM);

  coproto::sync_wait(sockets[0].send(w_mul_mask));
  coproto::sync_wait(sockets[0].recvResize(send_w_mul_mask));

  insert_commus("recv_fm_w_mul_mask", 0);
  spdlog::debug("[recv] w_mul_mask sent finished");

  fig9_ID_xr.resize(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    fig9_ID_xr[i] = send_w_mul_mask[i] / (u128)fm_mask[i + 1];
  }
  spdlog::debug("[recv] fig9_ID_xr computed finished");

  // final clean up
  // IDs.clear();
  // IDs.shrink_to_fit();
  // fm_mask.clear();
  // fm_mask.shrink_to_fit();
  // get_id_encoding.clear();
  // get_id_encoding.shrink_to_fit();
  // IDs_ct.clear();
  // mask_mul0_pt.clear();
}