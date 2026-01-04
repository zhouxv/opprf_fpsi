#include "fpsi_recv.h"
#include "config.h"
#include "opprf/Defines.h"
#include "opprf/Opprf.h"
#include "opprf/SimpleIndex.h"
#include "pis_new/batch_peqt.h"
#include "pis_new/batch_pis_new.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/commu_util.h"
#include "utils/data_conversion_util.h"
#include "utils/dist_util.h"
#include "utils/okvs_util.h"
#include "utils/params_selects.h"
#include "utils/set_dec.h"
#include "utils/simpleTimer.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <fmt/core.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <spdlog/spdlog.h>

void FPSIRecv::DFmap_fig8_offline() {
  auto t = DELTA * 2 + 1;
  DFMAP_PARAM = LpParamTable::getSelectedParam(t);

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

  RsOpprfSender sender;

  coproto::sync_wait(sender.send(opprf_size_other, dfmap_opprf_keys,
                                 dfmap_opprf_values, recv_prng, 1, sockets[0]));

  spdlog::debug("recv fig8 ids size: {}", fig8_ID_xr.size());
}

/*
For avoiding value overflow, we use the following method to compute IDs:
1. random_values is u32 type (recv_prng.get<u32>() >> bits_num).
IDs is u64 type. ID is the sum of DIM random_values.
2. fm_mask_mul0(u64) fm_mask(u32), fm_mask_mul0[i] = fm_mask[0] * fm_mask[i+1].
3. u=(v+ID)*fm_mask_mul0. The computation will not overflow since BigNumber.
(max value 2^96)
4. w = u * mask[0]. (max value 2^128)
*/
void FPSIRecv::getID() {
  simpleTimer get_id_timer;

  vector<vector<pair<u64, u64>>> intervals(DIM); // intervals

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // computes random numbers
  vector<u32> random_values(PTS_NUM * DIM, 0);
  // vector<BigNumber> random_values_bns(PTS_NUM * DIM, 0);

  auto bits_num = (DIM <= 1) ? 1 : std::bit_width(DIM - 1);
  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = recv_prng.get<u32>() >> bits_num;
    // random_values_bns[i] =
    //     BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  get_id_timer.start();
  ipcl::PlainText randoms_pt = ipcl::PlainText(random_values);
  ipcl::CipherText random_ciphers = fmap_recv_key.pub_key.encrypt(randoms_pt);
  get_id_timer.end("recv_getid_random_enc");
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

  get_id_timer.start();
  rb_okvs.encode(get_id_keys, get_id_values, value_block_length,
                 get_id_encoding);
  get_id_timer.end("recv_getid_encoding");

  spdlog::debug("getID() computation completed");

  fpsi_timer.merge(get_id_timer);
}

void FPSIRecv::DFmap_fig9_offline() {
  simpleTimer fig9_offline;

  fig9_offline.start();
  getID();
  fig9_offline.end("recv_offline_getid");
  spdlog::debug("\t[recv] getID finished");

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

  fig9_offline.start();
  mask_mul0_pt = ipcl::PlainText(fm_mask_mul0_bn);
  IDs_ct = fmap_sender_key.pub_key.encrypt(ipcl::PlainText(IDs_bn));
  fig9_offline.end("recv_offline_ids_enc");

  ipcl::terminateContext();

  fpsi_timer.merge(fig9_offline);
}

void FPSIRecv::DFmap_fig9_offline_fake() {
  PRNG prng(oc::sysRandomSeed());
  IDs.resize(PTS_NUM, 0);
  prng.get(IDs.data(), IDs.size());

  u64 okvs_mN = PTS_NUM * DIM * 2;
  RBOKVS rb_okvs;
  rb_okvs.init(okvs_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  u64 okvs_mSize = rb_okvs.mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK;

  get_id_encoding =
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length));

  for (auto &row : get_id_encoding) {
    prng.get(row.data(), row.size());
  }

  spdlog::debug("\t[recv] getID fake finished");

  fm_mask.resize(PTS_NUM + 1, 0);
  prng.get(fm_mask.data(), fm_mask.size());

  vector<BigNumber> IDs_bn(PTS_NUM);

  vector<u64> fm_mask_mul0(PTS_NUM, 0);
  vector<BigNumber> fm_mask_mul0_bn(PTS_NUM);
  prng.get(fm_mask_mul0.data(), fm_mask_mul0.size());

  vector<u32> cipher_vecu32(128);
  for (u64 i = 0; i < PTS_NUM; i++) {
    prng.get(cipher_vecu32.data(), 128);
    fm_mask_mul0_bn[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&fm_mask_mul0[i]), 2);
    IDs_bn[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(cipher_vecu32.data()), 128);
  }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  mask_mul0_pt = ipcl::PlainText(fm_mask_mul0_bn);
  IDs_ct = ipcl::CipherText(fmap_sender_key.pub_key, IDs_bn);

  ipcl::terminateContext();

  spdlog::debug("\t[recv] DFmap_fig9_offline_fake finished");
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

  coproto::sync_wait(sockets[0].flush());
  insert_commus("recv_fm_get_id_encodings", 0);
  spdlog::debug("\t[recv] getID encodings sent finished");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // receive send_get_id_encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 get_id_value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK;

  vector<block> flatten_get_id_encodings(get_id_mSize *
                                         get_id_value_block_length);

  coproto::sync_wait(sockets[0].recvResize(flatten_get_id_encodings));

  auto send_encoding =
      chunkFixedSizeBlocks(flatten_get_id_encodings, get_id_value_block_length);

  spdlog::debug("\t[send] received get_id_encodings");

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

  spdlog::debug("\t[recv] send_encoding decoded finished");

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
  spdlog::debug("\t[recv] homomorphic addition finished");

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
  //   cout << fmt::format("\t[recv] IDs2 [{}] {} {} {} {} {} {}", i, tmp_,
  //                       fm_mask[0], fm_mask[i + 1],
  //                       (u64)fm_mask[0] * (u64)fm_mask[i + 1],
  //                       (u128)fm_mask[0] * (u128)fm_mask[i + 1] * tmp_,
  //                       tmp2_)
  //        << endl;
  // }

  spdlog::debug("\t[recv] compute u finished");

  coproto::sync_wait(
      sockets[0].send(bignumers_to_block_vector(u_cts.getTexts())));
  coproto::sync_wait(sockets[0].flush());
  insert_commus("recv_fm_u_cts", 0);

  spdlog::debug("\t[recv] u_cts sent finished");

  vector<block> send_u_cts_blks(PTS_NUM * PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(send_u_cts_blks));

  vector<BigNumber> send_u_cts_bn =
      block_vector_to_bignumers(send_u_cts_blks, PTS_NUM);

  auto w_pt = fmap_recv_key.priv_key.decrypt(
      ipcl::CipherText(fmap_recv_key.pub_key, send_u_cts_bn));
  spdlog::debug("\t[recv] decrypt w finished");

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
  coproto::sync_wait(sockets[0].flush());
  insert_commus("recv_fm_w_mul_mask", 0);
  spdlog::debug("\t[recv] w_mul_mask sent finished");

  fig9_ID_xr.resize(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    fig9_ID_xr[i] = send_w_mul_mask[i] / (u128)fm_mask[i + 1];
  }
  spdlog::debug("\t[recv] fig9_ID_xr computed finished");
}

void FPSIRecv::psi_offline() {
  simpleTimer psi_offline_timer;
  psi_offline_timer.start();
  DFmap_fig9_offline();
  psi_offline_timer.end("recv_offline_fmap");

  fpsi_timer.merge(psi_offline_timer);
}

void FPSIRecv::psi_offline_fake() {
  simpleTimer psi_offline_fake_timer;
  DFmap_fig9_offline_fake();

  fpsi_timer.merge(psi_offline_fake_timer);
}

void FPSIRecv::psi_online() {
  simpleTimer psi_online_timer;

  /* ---------------------------------------------------------------------------*/
  // step 1: (1,1)-DFmap recv
  /* ---------------------------------------------------------------------------*/
  psi_online_timer.start();
  DFmap_fig9_online();
  psi_online_timer.end("recv_DFmap_fig9_online");
  // DFmap_fig9_clear();
  spdlog::info("  Recv step1: fmap finished!");

  /* ---------------------------------------------------------------------------*/
  // step 2: recv simple hash
  /* ---------------------------------------------------------------------------*/
  vector<block> ids_blks(PTS_NUM);
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  for (u64 i = 0; i < PTS_NUM; i++) {
    blake3_hasher_update(&hasher, &fig9_ID_xr[i], sizeof(fig9_ID_xr[i]));
    blake3_hasher_finalize(&hasher, ids_blks[i].data(), 16);
    blake3_hasher_reset(&hasher);
  }

  // for (u64 i = 0; i < 10; i++) {
  //   spdlog::debug("\t[recv] {} {} {}", i, fig9_ID_xr[i], ids_blks[i]);
  // }

  psi_online_timer.start();
  CuckooIndex<NotThreadSafe> cuckoo_table;
  cuckoo_table.init(PTS_NUM, CUCKOO_SEC_PARAM, STASH_SIZE, NUM_HASH_FUNC);
  SimpleIndex simple_table;
  simple_table.init(cuckoo_table.mNumBins, PTS_NUM);

  simple_table.insert(ids_blks);
  psi_online_timer.end("recv_simple_hash");

  // for (u64 i = 0; i < 5; i++) {
  //   spdlog::debug("\t[send] simple index: {}, value: {}, hashindex:{} {} {}",
  //   i,
  //                 ids_blks[i], simple_table.mLocations(i, 0),
  //                 simple_table.mLocations(i, 1), simple_table.mLocations(i,
  //                 2));

  //   for (u64 j = 0; j < simple_table.mMaxBinSize; j++) {
  //     spdlog::debug(
  //         "simple hash bin [{}] {} {}", simple_table.mLocations(i, 0),
  //         simple_table.mBins(simple_table.mLocations(i, 0), j).hashIdx(),
  //         simple_table.mBins(simple_table.mLocations(i, 0), j).idx());
  //   }
  // }

  // simple_table.print();
  spdlog::debug(
      "\t[recv] simple num_balls: {} , num_bins : {}, bin_max_size : {}",
      PTS_NUM, simple_table.mNumBins, simple_table.mMaxBinSize);

  spdlog::info("  Recv step2: simple hash finished!");

  /* ---------------------------------------------------------------------------*/
  // step 3: recv mp_ssFMat
  /* ---------------------------------------------------------------------------*/
  psi_online_timer.start();
  if (METRIC == 0) {
    mp_ssFMat_linf(simple_table);
  } else {
    mp_ssFMat_lp(simple_table);
  }
  psi_online_timer.end("recv_ssFmat");

  spdlog::info("  Recv step3: mp_ssFMath_L{} finished!",
               (METRIC == 0) ? "inf" : std::to_string(METRIC));

  /* ---------------------------------------------------------------------------*/
  // step 4: recv PSI OT
  /* ---------------------------------------------------------------------------*/
  SilentOtExtReceiver s_ot_recv;
  u64 numOTs = cuckoo_table.mNumBins;
  s_ot_recv.configure(numOTs, 2, 1, SilentSecType::SemiHonest,
                      SdNoiseDistribution::Regular, DefaultMultType);

  //  gen baseOT
  coproto::sync_wait(s_ot_recv.genBaseCors(recv_prng, sockets[0]));

  std::vector<block> ot_messages(numOTs);

  psi_online_timer.start();
  // gen randomOT
  auto proto = s_ot_recv.receive(ee, ot_messages, recv_prng, sockets[0]);
  // auto protocol = s_ot_recv.silentReceive(ee, ot_messages, recv_prng,
  //                                         sockets[0], OTType::Correlated);
  cp::sync_wait(proto);

  // randomOT -> OT
  vector<block> mask_msg_0(numOTs);
  vector<block> mask_msg_1(numOTs);
  coproto::sync_wait(sockets[0].recv(mask_msg_0));
  coproto::sync_wait(sockets[0].recv(mask_msg_1));

  vector<u64> recvMsgs(numOTs);
  for (u64 i = 0; i < numOTs; i++) {
    auto tmp_blk = (ee[i]) ? (ot_messages[i] ^ mask_msg_1[i])
                           : (ot_messages[i] ^ mask_msg_0[i]);
    recvMsgs[i] = tmp_blk.get<u64>()[0];
  }
  psi_online_timer.end("recv_psi_ot");

  spdlog::info("  Recv step4: recv OTs finished!");

  psi_online_timer.start();
  std::vector<std::pair<u64, u64>> find_table;
  for (u64 i = 0; i < PTS_NUM; i++) {
    find_table.emplace_back(fig9_ID_xr[i], i);
  }
  std::sort(find_table.begin(), find_table.end());

  // lookup
  vector<u64> intersection_idxs;
  for (auto msg : recvMsgs) {
    auto it = std::lower_bound(find_table.begin(), find_table.end(), msg,
                               [](auto &p, u64 k) { return p.first < k; });

    if (it != find_table.end() && it->first == msg) {
      intersection_idxs.push_back(it->second);
    }
  }

  intersection_idxs_tmp = intersection_idxs;
  psi_online_timer.end("recv_psi_intersection");

  fpsi_timer.merge(psi_online_timer);
}

void FPSIRecv::mp_ssFMat_linf(SimpleIndex &st) {
  simpleTimer fmat_timer;

  // get set_dec and set_prefix param
  auto prefix_param = LinfParamTable::getSelectedParam(2 * DELTA + 1);

  u64 bins_num = st.mNumBins;
  auto &tmp_idxs = st.mLocations;

  u64 a_random_size = bins_num * DIM;
  vector<block> a_random(a_random_size);
  recv_prng.get(a_random.data(), a_random_size);

  oc::Matrix<block> rr_vals(DIM, bins_num, osuCrypto::AllocType::Zeroed);

  auto dim_thread = [&](u64 dim_index) {
    simpleTimer dim_thread_timer;
    PRNG prng(oc::sysRandomSeed());

    /* ---------------------------------------------------------------------------*/
    // step 1: recv getList
    /* ---------------------------------------------------------------------------*/
    vector<block> prefix_keys;
    vector<block> prefix_vals;
    u64 opprf_size(prefix_param.second * PTS_NUM * NUM_HASH_FUNC);
    prefix_keys.reserve(opprf_size);
    prefix_vals.reserve(opprf_size);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    for (u64 i = 0; i < PTS_NUM; i++) {
      auto prefixs = set_dec(pts[i][dim_index] - DELTA,
                             pts[i][dim_index] + DELTA, prefix_param.first);
      for (auto prefix : prefixs) {
        for (u64 k = 0; k < NUM_HASH_FUNC; k++) {
          block hash_out;
          u64 bin_idx = tmp_idxs[i][k];
          blake3_hasher_update(&hasher, prefix.data(), prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_xr[i], sizeof(u64));
          blake3_hasher_update(&hasher, &k, sizeof(u64));
          blake3_hasher_update(&hasher, &bin_idx, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);
          prefix_vals.push_back(a_random[dim_index * bins_num + bin_idx]);
        }
      }
    }

    // spdlog::debug("\t[recv] mp_ssFMat thread [{}] —— keys size: {} , value "
    //               "size : {}; expect size : {} ",
    //               dim_index, prefix_keys.size(), prefix_vals.size(),
    //               opprf_size);

    padding_keys(prefix_keys, opprf_size);
    padding_keys(prefix_vals, opprf_size);

    if (dim_index == 0)
      spdlog::info("\t[recv] mp_ssFMat thread [{}] —— step1 getlist finished!",
                   dim_index);

    /* ---------------------------------------------------------------------------*/
    // step 3: bOPPRF RsOpprfSender
    /* ---------------------------------------------------------------------------*/
    u64 opprf_size_other;
    coproto::sync_wait(sockets[dim_index].send(opprf_size));
    coproto::sync_wait(sockets[dim_index].recv(opprf_size_other));

    RsOpprfSender opprf_sender;

    dim_thread_timer.start();
    coproto::sync_wait(opprf_sender.send(opprf_size_other, prefix_keys,
                                         prefix_vals, prng, 1,
                                         sockets[dim_index]));
    dim_thread_timer.end(fmt::format("recv_{}_fmat_step3_opprf", dim_index));
    insert_commus(fmt::format("recv_{}_fmat_step3", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::info(
          "\t[recv] mp_ssFMat thread [{}] —— step3 RsOpprfSender finished!",
          dim_index);

    /* ---------------------------------------------------------------------------*/
    // step 4: bOPPRF RsOpprfReceiver
    /* ---------------------------------------------------------------------------*/
    RsOpprfReceiver opprf_recv;

    dim_thread_timer.start();
    coproto::sync_wait(opprf_recv.receive(
        opprf_size_other,
        coproto::span<block>(a_random.data() + bins_num * dim_index, bins_num),
        rr_vals[dim_index], prng, 1, sockets[dim_index]));
    dim_thread_timer.end(fmt::format("recv_{}_fmat_step4_opprf", dim_index));

    insert_commus(fmt::format("recv_{}_fmat_step4", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::info(
          "\t[recv] mp_ssFMat thread [{}] —— step4 RsOpprfReceiver finished!",
          dim_index);

    fpsi_timer.merge(dim_thread_timer);
  };

  vector<thread> dim_threads;
  fmat_timer.start();
  // start dim threads
  for (u64 t = 0; t < DIM; t++) {
    dim_threads.emplace_back(dim_thread, t);
  }

  // wait for getList threads
  for (auto &th : dim_threads) {
    th.join();
  }

  /* ---------------------------------------------------------------------------*/
  // step 5: recv ssPEQT
  /* ---------------------------------------------------------------------------*/
  vector<block> rr_vals_sums(bins_num, ZeroBlock);
  for (u64 i = 0; i < rr_vals_sums.size(); i++) {
    for (u64 j = 0; j < DIM; j++) {
      rr_vals_sums[i] ^= rr_vals[j][i];
    }
  }

  fmat_timer.start();
  auto e = Batch_PEQT_recv<block>(rr_vals_sums, sockets[0]);
  ee = sync_wait(e);
  fmat_timer.end("recv_fmat_step5_batch_peqt");
  insert_commus("recv_fmat_step5_batch_peqt", 0);

  // for (u64 i = 0; i < 10; i++) {
  //   spdlog::debug("recv bins[{}] {} {}", i, rr_vals_sums[i], ee[i]);
  // }

  fmat_timer.end("recv_fmat_threads_all");

  fpsi_timer.merge(fmat_timer);
}

void FPSIRecv::mp_ssFMat_lp(SimpleIndex &st) {
  simpleTimer fmat_timer;

  // get set_dec and set_prefix param
  auto delta_plus_param = LpParamTable::getSelectedParam(DELTA + 1);
  auto delta_param = LpParamTable::getSelectedParam(DELTA);

  // obtain tmp idxs
  auto &tmp_idxs = st.mLocations;

  // prepare getList a_random
  u64 bins_num = st.mNumBins;
  u64 a_random_size = bins_num * DIM * (METRIC + 1);

  // generate a_random
  vector<u32> a_random(a_random_size);
  for (u64 i = 0; i < a_random_size; i++) {
    a_random[i] = recv_prng.get<u32>() >> 1;
  }
  u64 a_random_stride = DIM * (METRIC + 1);

  auto dim_thread = [&](u64 dim_index) {
    simpleTimer dim_thread_timer;
    PRNG prng(oc::sysRandomSeed());

    /*---------------------------------------------------------------------------*/
    // step 1: recv getList_lp
    /*---------------------------------------------------------------------------*/
    u64 opprf_size((delta_plus_param.second + delta_param.second) * PTS_NUM *
                   NUM_HASH_FUNC);
    vector<block> prefix_keys;
    oc::Matrix<u32> prefix_vals(opprf_size, METRIC + 1);
    prefix_keys.reserve(opprf_size);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    u64 val_index = 0;
    u64 sigma0(0), sigma1(1);
    for (u64 i = 0; i < PTS_NUM; i++) {
      auto pt_dim = pts[i][dim_index];
      auto x_0 = set_dec(pt_dim - DELTA, pt_dim, delta_plus_param.first);
      auto x_1 = set_dec(pt_dim + 1, pt_dim + DELTA, delta_param.first);

      // key = H(prefix || ID_xr || k || bin_idx || σ=0)
      for (auto x0_prefix : x_0) {
        auto x_star_0 = up_bound(x0_prefix);
        auto diff = pt_dim - x_star_0;

        for (u64 k = 0; k < NUM_HASH_FUNC; k++) {
          block hash_out;
          u64 bin_idx = tmp_idxs[i][k];
          blake3_hasher_update(&hasher, x0_prefix.data(), x0_prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_xr[i], sizeof(u64));
          blake3_hasher_update(&hasher, &k, sizeof(u64));
          blake3_hasher_update(&hasher, &bin_idx, sizeof(u64));
          blake3_hasher_update(&hasher, &sigma0, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);

          auto tmp_a_idx = bin_idx * a_random_stride + dim_index * (METRIC + 1);
          for (u64 p_index = 0; p_index <= METRIC; p_index++) {
            if (p_index == 0) {
              prefix_vals[val_index][p_index] = a_random[tmp_a_idx + p_index];
            } else {
              prefix_vals[val_index][p_index] =
                  a_random[tmp_a_idx + p_index] + fast_pow(diff, p_index);
            }
          }
          val_index++;
        }
      }

      // key = H(prefix || ID_xr || k || bin_idx || σ=1)
      for (auto x1_prefix : x_1) {
        auto x_star_1 = low_bound(x1_prefix);
        auto diff = x_star_1 - pt_dim;
        for (u64 k = 0; k < NUM_HASH_FUNC; k++) {
          block hash_out;
          u64 bin_idx = tmp_idxs[i][k];
          blake3_hasher_update(&hasher, x1_prefix.data(), x1_prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_xr[i], sizeof(u64));
          blake3_hasher_update(&hasher, &k, sizeof(u64));
          blake3_hasher_update(&hasher, &bin_idx, sizeof(u64));
          blake3_hasher_update(&hasher, &sigma1, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);

          auto tmp_a_idx = bin_idx * a_random_stride + dim_index * (METRIC + 1);
          for (u64 p_index = 0; p_index <= METRIC; p_index++) {
            if (p_index == 0) {
              prefix_vals[val_index][p_index] = a_random[tmp_a_idx + p_index];
            } else {
              prefix_vals[val_index][p_index] =
                  a_random[tmp_a_idx + p_index] + fast_pow(diff, p_index);
            }
          }
          val_index++;
        }
      }
    }

    // if (dim_index == 0)
    //   spdlog::debug("\t[recv] mp_ssFMat thread [{}] —— keys size: {} , value
    //   "
    //                 "size : {}; expect size : {} ",
    //                 dim_index, prefix_keys.size(), prefix_vals.size(),
    //                 opprf_size);

    // padding matrix vals
    prng.get(prefix_vals.data() + prefix_keys.size() * (METRIC + 1),
             (opprf_size - prefix_keys.size()) * (METRIC + 1));

    // padding keys and vals
    padding_keys(prefix_keys, opprf_size);

    if (dim_index == 0)
      spdlog::debug("\t[recv] mp_ssFMat thread [{}] —— keys size: {} , value "
                    "size : {}; expect size : {} ",
                    dim_index, prefix_keys.size(), prefix_vals.size(),
                    opprf_size);

    if (dim_index == 0)
      spdlog::info("\t[recv] mp_ssFMat thread [{}] —— step1 getlist finished !",
                   dim_index);

    /*---------------------------------------------------------------------------*/
    // step 3: bOPPRF RsOpprfSender
    /*---------------------------------------------------------------------------*/
    u64 opprf_size_other;
    coproto::sync_wait(sockets[dim_index].send(opprf_size));
    coproto::sync_wait(sockets[dim_index].recv(opprf_size_other));

    RsOpprfSender opprf_sender;

    dim_thread_timer.start();
    coproto::sync_wait(opprf_sender.send(opprf_size_other, prefix_keys,
                                         prefix_vals, prng, 1,
                                         sockets[dim_index]));
    dim_thread_timer.end(fmt::format("recv_{}_fmat_step3_opprf", dim_index));
    insert_commus(fmt::format("recv_{}_fmat_step3", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::info(
          "\t[recv] mp_ssFMat thread [{}] —— step3 RsOpprfSender finished!",
          dim_index);

    /*---------------------------------------------------------------------------*/
    // step 4: PIS sender
    /*---------------------------------------------------------------------------*/
    vector<u32> a0(bins_num);
    for (u64 bin_idx = 0; bin_idx < bins_num; bin_idx++) {
      a0[bin_idx] =
          a_random[bin_idx * a_random_stride + dim_index * (METRIC + 1)];
    }
    u64 batch_size = delta_param.first.size() + delta_plus_param.first.size();
    u64 batch_num = bins_num;

    dim_thread_timer.start();
    auto pis_sender =
        Batch_PIS_send_new(a0, batch_size, batch_num, sockets[dim_index]);
    sync_wait(pis_sender);
    dim_thread_timer.end(fmt::format("recv_{}_fmat_step4_pis", dim_index));

    insert_commus(fmt::format("recv_{}_pis_step4", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::info(
          "\t[recv] mp_ssFMat thread [{}] —— step4 PIS sender finished!",
          dim_index);

    /*---------------------------------------------------------------------------*/
    // step 5: copute v_
    /*---------------------------------------------------------------------------*/

    fpsi_timer.merge(dim_thread_timer);
  };

  vector<thread> dim_threads;
  fmat_timer.start();
  // start dim threads
  for (u64 t = 0; t < DIM; t++) {
    dim_threads.emplace_back(dim_thread, t);
  }

  // wait for getList threads
  for (auto &th : dim_threads) {
    th.join();
  }
  fmat_timer.end("recv_fmat_threads_all_lp");

  /*---------------------------------------------------------------------------*/
  // step 5: copute v_ and F_ssIFMatch
  /*---------------------------------------------------------------------------*/
  vector<u64> v_sums(bins_num, 0);
  for (u64 i = 0; i < bins_num; i++) {
    for (u64 j = 0; j < DIM; j++) {
      v_sums[i] += a_random[i * a_random_stride + j * (METRIC + 1) + 1];
    }
    v_sums[i] += fast_pow(DELTA, METRIC) / 2;
  }

  fmat_timer.start();
  ssIFMat_recv(v_sums);
  fmat_timer.end("recv_fmat_step5_ssifmat_lp");

  insert_commus("recv_fmat_step5_ssifmat_lp", 0);

  fpsi_timer.merge(fmat_timer);
}

// one dimension ssIFMat recv
void FPSIRecv::ssIFMat_recv(const oc::span<u64> &v_sums) {
  u64 bins_num = v_sums.size();
  PRNG prng(oc::sysRandomSeed());

  /* ---------------------------------------------------------------------------*/
  // step 1: Recv ssIFMat Set_Dec
  /* ---------------------------------------------------------------------------*/
  auto prefix_param = LinfParamTable::getSelectedParam(2 * DELTA + 1);

  u64 a_random_size = bins_num;
  vector<block> a_random(a_random_size);
  recv_prng.get(a_random.data(), a_random_size);

  vector<block> prefix_keys;
  vector<block> prefix_vals;
  u64 opprf_size(prefix_param.second * bins_num);
  prefix_keys.reserve(opprf_size);
  prefix_vals.reserve(opprf_size);

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  for (u64 i = 0; i < bins_num; i++) {
    auto prefixs =
        set_dec(v_sums[i] - DELTA, v_sums[i] + DELTA, prefix_param.first);
    for (auto prefix : prefixs) {
      block hash_out;
      blake3_hasher_update(&hasher, prefix.data(), prefix.size());
      blake3_hasher_update(&hasher, &i, sizeof(u64));
      blake3_hasher_finalize(&hasher, hash_out.data(), 16);
      blake3_hasher_reset(&hasher);
      prefix_keys.push_back(hash_out);
      prefix_vals.push_back(a_random[i]);
    }
  }

  padding_keys(prefix_keys, opprf_size);
  padding_keys(prefix_vals, opprf_size);

  spdlog::debug("\t  [recv] ssIFMat —— step1 set_dec finished! keys size: {} , "
                "value size : {}; expect size : {} ",
                prefix_keys.size(), prefix_vals.size(), opprf_size);

  /* ---------------------------------------------------------------------------*/
  // step 2: Recv ssIFMat bOPPRF
  /* ---------------------------------------------------------------------------*/
  u64 opprf_size_other;
  coproto::sync_wait(sockets[0].send(opprf_size));
  coproto::sync_wait(sockets[0].recv(opprf_size_other));

  RsOpprfSender opprf_sender;
  coproto::sync_wait(opprf_sender.send(opprf_size_other, prefix_keys,
                                       prefix_vals, prng, 1, sockets[0]));

  spdlog::debug("\t  [recv] ssIFMat —— step2 RsOpprfSender finished! ");

  /* ---------------------------------------------------------------------------*/
  // step 3: Recv ssIFMat bOPPRF2
  /* ---------------------------------------------------------------------------*/
  RsOpprfReceiver opprf_recv;
  vector<u64> t_(bins_num);

  coproto::sync_wait(opprf_recv.receive(
      opprf_size_other, a_random, oc::span<u64>(t_), prng, 1, sockets[0]));

  spdlog::debug("\t  [recv] ssIFMat —— step3 bOPPRF2 finished! ");

  /* ---------------------------------------------------------------------------*/
  // step 4: Recv ssIFMat ssPEQT
  /* ---------------------------------------------------------------------------*/
  auto e = Batch_PEQT_recv<u64>(t_, sockets[0]);
  ee = sync_wait(e);
  spdlog::debug("\t  [recv] ssIFMat —— step4 Batch_PEQT_recv finished! ");
}