#include "fpsi_sender.h"
#include "config.h"
#include "opprf/Defines.h"
#include "opprf/Opprf.h"
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

#include <algorithm>
#include <cmath>
#include <coproto/Common/macoro.h>
#include <coproto/Common/span.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <fmt/format.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <libOTe/Vole/Silent/SilentVoleSender.h>
#include <spdlog/spdlog.h>
#include <vector>

void FPSISender::DFmap_fig8_offline() {
  // In our implementation, the probability that φ(x) equals 0 is high.
  u64 φ = 0;

  // Compute block_4delta
  vector<u64> block_4delta(PTS_NUM * DIM);
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      block_4delta[pt_idx * DIM + dim_idx] =
          (pts[pt_idx][dim_idx] - DELTA) / SIDE_LEN;
    }
  }

  // Compute t_y_j
  t_y_j.resize(PTS_NUM * DIM);
  for (u64 pt_idx = 0; pt_idx < PTS_NUM; pt_idx++) {
    for (u64 dim_idx = 0; dim_idx < DIM; dim_idx++) {
      t_y_j[pt_idx * DIM + dim_idx] =
          get_fmap_opprf_key(dim_idx, block_4delta[pt_idx * DIM + dim_idx], φ,
                             block_4delta[pt_idx * DIM + φ]);
    }
  }

  spdlog::info("\tSender DFmap_fig8_offline finished");
}

void FPSISender::DFmap_fig8_online() {
  u64 opprf_size_other;
  u64 opprf_size = t_y_j.size();
  coproto::sync_wait(sockets[0].recv(opprf_size_other));
  coproto::sync_wait(sockets[0].send(opprf_size));

  RsOpprfReceiver recv;
  vector<block> opprf_values(opprf_size);

  coproto::sync_wait(recv.receive(opprf_size_other, t_y_j, opprf_values,
                                  sender_prng, 1, sockets[0]));

  fig8_ID_ys = opprf_values;

  // spdlog::debug("sender fig8 ids size: {}", fig8_ID_ys.size());

  // dfmap_opprf_0_keys.clear();
  // dfmap_opprf_0_keys.shrink_to_fit();
  // dfmap_opprf_1_vals.clear();
  // dfmap_opprf_1_vals.shrink_to_fit();
  // t_y_i.clear();
  // t_y_i.shrink_to_fit();

  spdlog::info("\tSender DFmap_fig8_online finished");
}

void FPSISender::getID() {
  simpleTimer get_id_timer;

  vector<vector<pair<u64, u64>>> intervals(DIM); // intervals

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // computes random numbers
  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_values_bns(PTS_NUM * DIM, 0);
  auto bits_num = (DIM <= 1) ? 0 : std::bit_width(DIM - 1);
  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = sender_prng.get<u32>() >> bits_num;
    random_values_bns[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  get_id_timer.start();
  ipcl::PlainText randoms_pt = ipcl::PlainText(random_values_bns);
  ipcl::CipherText random_ciphers = fmap_sender_key.pub_key.encrypt(randoms_pt);
  get_id_timer.end("sender_getid_random_enc");
  ipcl::terminateContext();

  spdlog::debug("\t[send] getID() random numbers computed");

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

      for (size_t i = 1; i < interval.size(); i++) {
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

  spdlog::debug("\t[send] getID() interval merge finished");

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

  spdlog::debug("\t[send] getID() idx computation completed");

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
  get_id_timer.end("sender_getid_encoding");
  spdlog::debug("\t[send] getID() encoding finished");

  fpsi_timer.merge(get_id_timer);
}

void FPSISender::DFmap_fig9_offline() {
  simpleTimer fig9_offline;

  fig9_offline.start();
  getID();
  fig9_offline.end("sender_offline_getid");
  spdlog::debug("\t[send] getID finished");

  fm_mask.resize(PTS_NUM + 1, 0);
  vector<u64> fm_mask_mul0(PTS_NUM, 0);

  vector<BigNumber> fm_mask_mul0_bn(PTS_NUM);
  vector<BigNumber> IDs_bn(PTS_NUM);

  sender_prng.get(fm_mask.data(), fm_mask.size());
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
  IDs_ct = fmap_recv_key.pub_key.encrypt(ipcl::PlainText(IDs_bn));
  fig9_offline.end("sender_offline_ids_enc");
  ipcl::terminateContext();
  spdlog::debug("\t[send] mask_mul0_pt and IDs_ct encryption finished");

  fpsi_timer.merge(fig9_offline);
  spdlog::info("\tSender DFmap_fig9_offline finished");
}

void FPSISender::DFmap_fig9_offline_fake() {
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

  spdlog::debug("\t[send] getID fake finished");

  fm_mask.resize(PTS_NUM + 1, 0);
  prng.get(fm_mask.data(), fm_mask.size());

  vector<u64> fm_mask_mul0(PTS_NUM, 0);
  vector<BigNumber> fm_mask_mul0_bn(PTS_NUM);
  prng.get(fm_mask_mul0.data(), fm_mask_mul0.size());

  vector<BigNumber> IDs_bn(PTS_NUM);

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
  IDs_ct = ipcl::CipherText(fmap_recv_key.pub_key, IDs_bn);
  ipcl::terminateContext();
  spdlog::debug("\t[send] IDs_ct fake encryption finished");

  spdlog::info("\tSender DFmap_fig9_offline_fake finished");
}

void FPSISender::DFmap_fig9_online() {
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // receive recv_get_id_encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 get_id_mN = 0, get_id_mSize = 0;
  u64 get_id_value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK;

  coproto::sync_wait(sockets[0].recv(get_id_mN));
  coproto::sync_wait(sockets[0].recv(get_id_mSize));

  vector<block> flatten_get_id_encodings(get_id_mSize *
                                         get_id_value_block_length);

  coproto::sync_wait(sockets[0].recvResize(flatten_get_id_encodings));

  auto recv_encoding =
      chunkFixedSizeBlocks(flatten_get_id_encodings, get_id_value_block_length);

  spdlog::debug("\t[send] received get_id_encodings");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send getID encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  coproto::sync_wait(sockets[0].send(flattenBlocks(get_id_encoding)));
  coproto::sync_wait(sockets[0].flush());
  insert_commus("sender_fm_get_id_encodings", 0);
  spdlog::debug("\t[send] getID encodings sent finished");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // decode recv_encoding
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  RBOKVS rbokvs;
  rbokvs.init(get_id_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<vector<BigNumber>> decoded_bns(DIM);

  for (u64 i = 0; i < pts.size(); i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto decode = rbokvs.decode(
          recv_encoding, get_fmap_okvs_key(j, (pts[i][j] - DELTA) / SIDE_LEN),
          get_id_value_block_length);
      decoded_bns[j].push_back(block_vector_to_bignumer(decode));
    }
  }
  spdlog::debug("\t[send] recv_encoding decoded finished");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // homomorphic addition
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::CipherText v_add_res;
  for (u64 i = 0; i < DIM; i++) {
    auto temp = ipcl::CipherText(fmap_recv_key.pub_key, decoded_bns[i]);
    if (i == 0) {
      v_add_res = temp;
    } else {
      v_add_res = v_add_res + temp;
    }
  }

  spdlog::debug("\t[send] homomorphic addition finished");

  ipcl::terminateContext();

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step6 compute u
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto u_cts = (v_add_res + IDs_ct) * mask_mul0_pt;
  spdlog::debug("\t[send] compute u finished");

  // auto tmp_add = v_add_res + IDs_ct;
  // auto add_dec = fmap_recv_key.priv_key.decrypt(tmp_add);
  // auto u_dec = fmap_recv_key.priv_key.decrypt(u_cts);
  // for (u64 i = 0; i < 10; i++) {
  //   auto tmp = add_dec.getElementVec(i);
  //   u64 tmp_ = ((u64)tmp[1] << 32) | tmp[0];
  //   auto tmp2 = u_dec.getElementVec(i);
  //   u64 tmp2_ = ((u64)tmp2[1] << 32) | tmp2[0];
  //   cout << fmt::format("\t[send] IDs2 [{}] {} {} {} {} {} {}", i, tmp_,
  //                       fm_mask[0], fm_mask[i + 1],
  //                       (u64)fm_mask[0] * (u64)fm_mask[i + 1],
  //                       (u64)fm_mask[0] * (u64)fm_mask[i + 1] * tmp_, tmp2_)
  //        << endl;
  // }

  vector<block> recv_u_cts_blks(PTS_NUM * PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(recv_u_cts_blks));

  coproto::sync_wait(
      sockets[0].send(bignumers_to_block_vector(u_cts.getTexts())));
  coproto::sync_wait(sockets[0].flush());
  insert_commus("sender_fm_u_cts", 0);
  spdlog::debug("\t[send] u_cts sent finished");

  vector<BigNumber> recv_u_cts_bn =
      block_vector_to_bignumers(recv_u_cts_blks, PTS_NUM);

  auto w_pt = fmap_sender_key.priv_key.decrypt(
      ipcl::CipherText(fmap_sender_key.pub_key, recv_u_cts_bn));
  spdlog::debug("\t[send] decrypt w finished");

  vector<u128> w_mul_mask(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    auto tmp = w_pt.getElementVec(i);
    w_mul_mask[i] = ((u128)tmp[3] << 96) | ((u128)tmp[2] << 64) |
                    ((u128)tmp[1] << 32) | tmp[0];
    w_mul_mask[i] = w_mul_mask[i] * (u128)fm_mask[0];
  }

  vector<u128> recv_w_mul_mask(PTS_NUM);
  coproto::sync_wait(sockets[0].recvResize(recv_w_mul_mask));
  coproto::sync_wait(sockets[0].send(w_mul_mask));
  coproto::sync_wait(sockets[0].flush());

  insert_commus("sender_fm_w_mul_mask", 0);
  spdlog::debug("\t[send] w_mul_mask sent finished");

  fig9_ID_ys.resize(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    fig9_ID_ys[i] = recv_w_mul_mask[i] / (u128)fm_mask[i + 1];
  }
  spdlog::debug("\t[send] fig9_ID_ys computed finished");

  // final clean up
  // DFmap_fig9_clear();
  spdlog::info("\tSender DFmap_fig9_online finished");
}

void FPSISender::psi_offline() {
  simpleTimer psi_offline_timer;
  psi_offline_timer.start();
  DFmap_fig9_offline();
  psi_offline_timer.end("send_offline_fmap");

  if (METRIC > 1) {
    // slient VOLE sender
    CuckooIndex<ThreadSafe> ct;
    ct.init(PTS_NUM, CUCKOO_SEC_PARAM, STASH_SIZE, NUM_HASH_FUNC);

    u64 numVole = ct.mNumBins * DIM * (METRIC - 1);
    b_delta = sender_prng.get<u32>();
    d_vole.resize(numVole);

    // for (u64 i = 0; i < d_vole.size(); i++) {
    //   d_vole[i] = sender_prng.get<u16>();
    // }

    // vector<u32> a_tmp(numVole);
    // vector<u32> c_tmp(numVole);

    // cp::sync_wait(sockets[0].recvResize(a_tmp));
    // cp::sync_wait(sockets[0].flush());

    // for (u64 i = 0; i < numVole; i++) {
    //   c_tmp[i] = a_tmp[i] * b_delta + d_vole[i];
    // }

    // cp::sync_wait(sockets[0].send(c_tmp));
    // cp::sync_wait(sockets[0].flush());

    // for (u64 i = 0; i < 1; i++) {
    //   spdlog::debug("\t[send] VOLE a_vole[{}] d {} ; b {}", i, d_vole[i],
    //                 b_delta);
    // }

    SilentVoleSender<u32, u32> sender;
    sender.configure(numVole, SilentSecType::SemiHonest, DefaultMultType,
                     SilentBaseType::BaseExtend, SdNoiseDistribution::Regular);

    psi_offline_timer.start();
    auto proto = sender.silentSend(b_delta, d_vole, sender_prng, sockets[0]);
    cp::sync_wait(proto);
    psi_offline_timer.end("sender_offline_vole_sender");

    spdlog::info("\t[send] silent VOLE sender finished!");

    sockets[0].mImpl->mBytesReceived = 0;
    sockets[0].mImpl->mBytesSent = 0;
  }

  fpsi_timer.merge(psi_offline_timer);
  spdlog::info("  Sender psi_offline finished");
}

void FPSISender::psi_offline_fake() {

  DFmap_fig9_offline_fake();

  if (METRIC > 1) {
    CuckooIndex<ThreadSafe> ct;
    ct.init(PTS_NUM, CUCKOO_SEC_PARAM, STASH_SIZE, NUM_HASH_FUNC);

    u64 numVole = ct.mNumBins * DIM * (METRIC - 1);
    b_delta = sender_prng.get<u32>();
    d_vole.resize(numVole);
    sender_prng.get<u32>(d_vole.data(), d_vole.size());
  }

  spdlog::info("  Sender psi_offline_fake finished");
}

void FPSISender::psi_online() {
  simpleTimer psi_online_timer;

  /* ---------------------------------------------------------------------------*/
  // step 1: (1,1)-DFmap send
  /* ---------------------------------------------------------------------------*/
  psi_online_timer.start();
  DFmap_fig9_online();
  psi_online_timer.end("sender_DFmap_fig9_online");
  // DFmap_fig9_clear();

  spdlog::info("  Sender step1: fmap finished!");

  /* ---------------------------------------------------------------------------*/
  // step 2: sender cuckoo hash
  /* ---------------------------------------------------------------------------*/
  vector<block> ids_blks(PTS_NUM);
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  for (u64 i = 0; i < PTS_NUM; i++) {
    blake3_hasher_update(&hasher, &fig9_ID_ys[i], sizeof(fig9_ID_ys[i]));
    blake3_hasher_finalize(&hasher, ids_blks[i].data(), 16);
    blake3_hasher_reset(&hasher);
  }

  // for (u64 i = 0; i < 10; i++) {
  //   spdlog::debug("\t[send] {} {} {}", i, fig9_ID_ys[i], ids_blks[i]);
  // }

  psi_online_timer.start();
  CuckooIndex<ThreadSafe> cuckoo_table;
  cuckoo_table.init(PTS_NUM, CUCKOO_SEC_PARAM, STASH_SIZE, NUM_HASH_FUNC);
  cuckoo_table.insert(ids_blks);
  psi_online_timer.end("sender_cuckoo_hash");

  // for (u64 i = 0; i < 5; i++) {
  //   auto tmp = cuckoo_table.find(ids_blks[i]);
  //   spdlog::debug("\t[recv] cuckoo index: {}, value: {}, hashindex:{}", i,
  //                 cuckoo_table.mVals[tmp.mInputIdx], tmp.mCuckooPositon);

  //   spdlog::debug("\t[recv] cuckoo index: {}, value: {}, hashindex:{} {} {}",
  //   i,
  //                 ids_blks[i], cuckoo_table.mLocations(i, 0),
  //                 cuckoo_table.mLocations(i, 1), cuckoo_table.mLocations(i,
  //                 2));
  // }

  spdlog::debug("\t[send] cuckoo num_balls: {} , num_bins : {}",
                cuckoo_table.mParams.mN, cuckoo_table.mNumBins);

  spdlog::info("  Sender step2: cuckoo hash finished!");

  /* ---------------------------------------------------------------------------*/
  // step 3: sender mp_ssFMat
  /* ---------------------------------------------------------------------------*/
  psi_online_timer.start();

  if (METRIC == 0) {
    mp_ssFMat_linf(cuckoo_table);
  } else {
    mp_ssFMat_lp(cuckoo_table);
  }
  psi_online_timer.end("sender_ssFmat");

  spdlog::info("  Sender step3: mp_ssFMat_L{} finished!",
               (METRIC == 0) ? "inf" : std::to_string(METRIC));

  /* ---------------------------------------------------------------------------*/
  // step 4: sender PSI OT
  /* ---------------------------------------------------------------------------*/
  SilentOtExtSender s_ot_sender;
  u64 numOTs = cuckoo_table.mNumBins;
  s_ot_sender.configure(numOTs, 2, 1, SilentSecType::SemiHonest,
                        SdNoiseDistribution::Regular, DefaultMultType);

  psi_online_timer.start();

  //  gen baseOT
  cp::sync_wait(s_ot_sender.genBaseCors({}, sender_prng, sockets[0]));

  // gen randomOT
  std::vector<std::array<block, 2>> ot_messages(numOTs);
  auto proto = s_ot_sender.send(ot_messages, sender_prng, sockets[0]);
  // auto protocol = s_ot_sender.silentSend(ot_messages, sender_prng,
  // sockets[0]);
  cp::sync_wait(proto);

  // randomOT -> OT
  vector<block> half_sendMsg_0(numOTs);
  vector<block> half_sendMsg_1(numOTs);

  for (u64 i = 0; i < numOTs; i++) {
    auto tmp_bin = cuckoo_table.mBins[i];
    bool empty = tmp_bin.isEmpty();
    bool hit = ee[i];

    auto m0 = ot_messages[i][0];
    auto m1 = ot_messages[i][1];

    if (empty) {
      half_sendMsg_0[i] = sender_prng.get<block>() ^ m0;
      half_sendMsg_1[i] = sender_prng.get<block>() ^ m1;
    } else {
      auto pt_blk = block(fig9_ID_ys[tmp_bin.idx()]);
      if (hit) {
        half_sendMsg_0[i] = pt_blk ^ m0;
        half_sendMsg_1[i] = sender_prng.get<block>() ^ m1;
      } else {
        half_sendMsg_0[i] = sender_prng.get<block>() ^ m0;
        half_sendMsg_1[i] = pt_blk ^ m1;
      }
    }
  }

  coproto::sync_wait(sockets[0].send(half_sendMsg_0));
  coproto::sync_wait(sockets[0].send(half_sendMsg_1));
  psi_online_timer.end("sender_psi_ot");
  insert_commus("sender_psi_ot", 0);

  spdlog::info("  Sender step4: sender OTs finished!");

  fpsi_timer.merge(psi_online_timer);
}

template <CuckooTypes Mode>
void FPSISender::mp_ssFMat_linf(CuckooIndex<Mode> &ct) {
  simpleTimer fmat_timer;

  // get set_dec and set_prefix param
  auto prefix_param = LinfParamTable::getSelectedParam(2 * DELTA + 1);
  u64 bins_num = ct.mNumBins;

  vector<block> r_vals(bins_num * DIM);
  sender_prng.get(r_vals.data(), bins_num * DIM);
  u64 prefix_size = prefix_param.first.size();

  auto dim_thread = [&](u64 dim_index) {
    simpleTimer dim_thread_timer;
    PRNG prng(oc::sysRandomSeed());

    /* ---------------------------------------------------------------------------*/
    // step 2: send set_prefix
    /* ---------------------------------------------------------------------------*/
    vector<block> prefix_keys;
    u64 keys_size = prefix_size * bins_num;
    prefix_keys.reserve(keys_size);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    for (u64 i = 0; i < bins_num; i++) {

      if (ct.mBins[i].isEmpty()) {
        // for empty bin
        for (u64 j = 0; j < prefix_size; j++) {
          prefix_keys.push_back(prng.get<block>());
        }
      } else {
        auto tmp_bin = ct.mBins[i];
        u64 idx = tmp_bin.idx();
        u64 hash_idx = tmp_bin.hashIdx();
        auto prefixs = set_prefix(pts[idx][dim_index], prefix_param.first);
        for (auto prefix : prefixs) {
          block hash_out;
          blake3_hasher_update(&hasher, prefix.data(), prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_ys[idx], sizeof(u64));
          blake3_hasher_update(&hasher, &hash_idx, sizeof(u64));
          blake3_hasher_update(&hasher, &i, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);
        }
      }
    }

    // spdlog::debug(
    //     "\t[send] mp_ssFMat thread [{}] —— keys size: {} ; expect size:
    //     {}", dim_index, keys.size(), keys_size);

    if (dim_index == 0)
      spdlog::debug(
          "\t[send] mp_ssFMat thread [{}] —— step2 set_prefix finished!",
          dim_index);

    /* ---------------------------------------------------------------------------*/
    // step 3: bOPPRF RsOpprfReceiver
    /* ---------------------------------------------------------------------------*/
    u64 opprf_size_other;
    coproto::sync_wait(sockets[dim_index].recv(opprf_size_other));
    coproto::sync_wait(sockets[dim_index].send(keys_size));

    RsOpprfReceiver opprf_recv;
    vector<block> u(keys_size);

    dim_thread_timer.start();
    coproto::sync_wait(opprf_recv.receive(opprf_size_other, prefix_keys, u,
                                          prng, 1, sockets[dim_index]));
    dim_thread_timer.end(fmt::format("sender_{}_fmat_step3_opprf", dim_index));
    insert_commus(fmt::format("sender_{}_fmat_step3", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::debug("\t[send] mp_ssFMat thread [{}] —— step3 "
                    "RsOpprfReceiver finished!",
                    dim_index);

    /* ---------------------------------------------------------------------------*/
    // step 4: bOPPRF RsOpprfSender
    /* ---------------------------------------------------------------------------*/
    RsOpprfSender opprf_sender;
    vector<block> r_vals_(keys_size);
    for (u64 i = 0; i < bins_num; i++) {
      for (u64 j = 0; j < prefix_size; j++) {
        r_vals_[i * prefix_size + j] = r_vals[dim_index * bins_num + i];
      }
    }

    dim_thread_timer.start();
    coproto::sync_wait(
        opprf_sender.send(bins_num, u, r_vals_, prng, 1, sockets[dim_index]));
    dim_thread_timer.end(fmt::format("sender_{}_fmat_step4_opprf", dim_index));
    insert_commus(fmt::format("sender_{}_fmat_step4", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::debug(
          "\t[send] mp_ssFMat thread [{}] —— step4 RsOpprfSender finished!",
          dim_index);

    fpsi_timer.merge(dim_thread_timer);
  };

  vector<thread> dim_threads;
  fmat_timer.start();
  // start dim threads
  for (u64 t = 0; t < DIM; t++) {
    dim_threads.emplace_back(dim_thread, t);
  }

  // wait for dim threads
  for (auto &th : dim_threads) {
    th.join();
  }

  /* ---------------------------------------------------------------------------*/
  // step 5: sender ssPEQT
  /* ---------------------------------------------------------------------------*/
  vector<block> r_vals_sums(bins_num, ZeroBlock);
  for (u64 i = 0; i < r_vals_sums.size(); i++) {
    for (u64 j = 0; j < DIM; j++) {
      r_vals_sums[i] ^= r_vals[j * bins_num + i];
    }
  }

  fmat_timer.start();
  auto e = Batch_PEQT_send<block>(r_vals_sums, sockets[0]);
  ee = sync_wait(e);
  fmat_timer.end("sender_fmat_step5_batch_peqt");
  insert_commus("sender_fmat_step5_batch_peqt", 0);

  // for (u64 i = 0; i < 10; i++) {
  //   spdlog::debug("send bins[{}] {} {}", i, r_vals_sums[i], ee[i]);
  // }

  fmat_timer.end("sender_fmat_threads_all");

  fpsi_timer.merge(fmat_timer);
}

template <CuckooTypes Mode>
void FPSISender::mp_ssFMat_lp(CuckooIndex<Mode> &ct) {
  simpleTimer fmat_timer;

  // get set_dec and set_prefix param
  auto delta_plus_param = LpParamTable::getSelectedParam(DELTA + 1);
  auto delta_param = LpParamTable::getSelectedParam(DELTA);

  u64 bins_num = ct.mNumBins;

  u64 prefix_size_each_bin = delta_param.first.size() * 2;
  u64 vole_stride = DIM * (METRIC - 1);

  oc::Matrix<u32> u_(bins_num, DIM);

  auto dim_thread = [&](u64 dim_index) {
    simpleTimer dim_thread_timer;
    PRNG prng(oc::sysRandomSeed());

    /*---------------------------------------------------------------------------*/
    // step 2: send set_prefix
    /*---------------------------------------------------------------------------*/
    vector<block> prefix_keys;
    vector<u64> e;
    u64 keys_size = prefix_size_each_bin * bins_num;
    prefix_keys.reserve(keys_size);
    e.reserve(keys_size);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    u64 sigma0(0), sigma1(1);
    for (u64 i = 0; i < bins_num; i++) {
      if (ct.mBins[i].isEmpty()) {
        // for empty bin
        for (u64 j = 0; j < prefix_size_each_bin; j++) {
          prefix_keys.push_back(prng.get<block>());
          e.push_back(prng.get<u32>());
        }
      } else {
        auto tmp_bin = ct.mBins[i];
        u64 idx = tmp_bin.idx();
        u64 hash_idx = tmp_bin.hashIdx();
        auto prefixs_0 =
            set_prefix(pts[idx][dim_index], delta_plus_param.first);
        auto prefixs_1 = set_prefix(pts[idx][dim_index], delta_param.first);
        for (auto prefix : prefixs_0) {
          block hash_out;
          blake3_hasher_update(&hasher, prefix.data(), prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_ys[idx], sizeof(u64));
          blake3_hasher_update(&hasher, &hash_idx, sizeof(u64));
          blake3_hasher_update(&hasher, &i, sizeof(u64));
          blake3_hasher_update(&hasher, &sigma0, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);

          e.push_back(up_bound(prefix) - pts[idx][dim_index]);
        }
        for (auto prefix : prefixs_1) {
          block hash_out;
          blake3_hasher_update(&hasher, prefix.data(), prefix.size());
          blake3_hasher_update(&hasher, &fig9_ID_ys[idx], sizeof(u64));
          blake3_hasher_update(&hasher, &hash_idx, sizeof(u64));
          blake3_hasher_update(&hasher, &i, sizeof(u64));
          blake3_hasher_update(&hasher, &sigma1, sizeof(u64));
          blake3_hasher_finalize(&hasher, hash_out.data(), 16);
          blake3_hasher_reset(&hasher);
          prefix_keys.push_back(hash_out);

          e.push_back(pts[idx][dim_index] - low_bound(prefix));
        }
      }
    }

    if (dim_index == 0)
      spdlog::debug(
          "\t[send] mp_ssFMat thread [{}] —— step2 set_prefix finished!",
          dim_index);

    /*---------------------------------------------------------------------------*/
    // step 3: bOPPRF RsOpprfReceiver
    /*---------------------------------------------------------------------------*/
    u64 opprf_size_other;
    coproto::sync_wait(sockets[dim_index].recv(opprf_size_other));
    coproto::sync_wait(sockets[dim_index].send(keys_size));

    RsOpprfReceiver opprf_recv;
    oc::Matrix<u32> u(keys_size, METRIC + 1);

    dim_thread_timer.start();
    coproto::sync_wait(opprf_recv.receive(opprf_size_other, prefix_keys, u,
                                          prng, 1, sockets[dim_index]));
    dim_thread_timer.end(fmt::format("sender_{}_fmat_step3_opprf", dim_index));
    insert_commus(fmt::format("sender_{}_fmat_step3", dim_index), dim_index);

    if (dim_index == 0)
      spdlog::debug("\t[send] mp_ssFMat thread [{}] —— step3 "
                    "RsOpprfReceiver finished!",
                    dim_index);

    /*---------------------------------------------------------------------------*/
    // step 4: PIS recv
    /*---------------------------------------------------------------------------*/
    u64 batch_size = delta_param.first.size() + delta_plus_param.first.size();
    u64 batch_num = bins_num;

    auto fisrt_column = extract_column_fast(u, 0);

    dim_thread_timer.start();
    auto pis_recv = Batch_PIS_recv_new(fisrt_column, batch_size, batch_num,
                                       sockets[dim_index]);
    dim_thread_timer.end(fmt::format("sender_{}_fmat_step4_pis", dim_index));

    insert_commus(fmt::format("sender_{}_pis_step4", dim_index), dim_index);

    auto idxs = sync_wait(pis_recv);

    if (dim_index == 0)
      spdlog::debug("\t[send] mp_ssFMat thread [{}] —— step4 Batch_PIS_recv "
                    "finished!",
                    dim_index);
    // if (dim_index == 0) {
    //   for (u64 i = 0; i < 10; i++) {
    //     spdlog::debug("\t[send] dim [{}] pis idxs[{}] {}", dim_index, i,
    //                   idxs[i]);
    //   }
    // }

    /*---------------------------------------------------------------------------*/
    // step 5: compute u_
    /*---------------------------------------------------------------------------*/

    if (METRIC == 1) {
      // for metric == 1
      for (u64 i = 0; i < bins_num; i++) {
        auto pis_idx = idxs[i];
        auto tmp_idx = i * prefix_size_each_bin + pis_idx;
        u_[i][dim_index] = u[tmp_idx][1];
        if (!ct.mBins[i].isEmpty()) {
          u_[i][dim_index] += e[tmp_idx];
        }
      }
    } else {
      // for metric > 1
      vector<u32> v_si(bins_num * (METRIC - 1));
      for (u64 i = 0; i < bins_num; i++) {
        auto pis_idx = idxs[i];
        auto tmp_idx = i * prefix_size_each_bin + pis_idx;
        auto tmp_e = e[tmp_idx];

        u_[i][dim_index] = u[tmp_idx][METRIC] + fast_pow<u32>(tmp_e, METRIC);

        for (u64 s = 1; s < METRIC; s++) {
          u32 mid_val =
              combination<u32>(METRIC, s) * fast_pow<u32>(tmp_e, METRIC - s);
          u_[i][dim_index] +=
              mid_val * u[tmp_idx][s] -
              d_vole[i * vole_stride + dim_index * (METRIC - 1) + (s - 1)];
          v_si[i * (METRIC - 1) + (s - 1)] = mid_val + b_delta;
        }
      }

      cp::sync_wait(sockets[dim_index].send(v_si));
      cp::sync_wait(sockets[dim_index].flush());
      insert_commus(fmt::format("sender_{}_fmat_vis", dim_index), dim_index);
    }

    fpsi_timer.merge(dim_thread_timer);
  };

  vector<thread> dim_threads;
  fmat_timer.start();
  // start dim threads
  for (u64 t = 0; t < DIM; t++) {
    dim_threads.emplace_back(dim_thread, t);
  }

  // wait for dim threads
  for (auto &th : dim_threads) {
    th.join();
  }
  fmat_timer.end("sender_fmat_threads_all_lp");

  /*---------------------------------------------------------------------------*/
  // step 5: copute v_ and F_ssIFMatch
  /*---------------------------------------------------------------------------*/
  vector<u64> u_sums(bins_num, 0);
  for (u64 i = 0; i < bins_num; i++) {
    for (u64 j = 0; j < DIM; j++) {
      u_sums[i] += u_[i][j];
    }
  }

  fmat_timer.start();
  ssIFMat_send(oc::span<u64>(u_sums));
  fmat_timer.end("sender_fmat_step5_ssifmat_lp");

  insert_commus("sender_fmat_step5_ssifmat_lp", 0);

  fpsi_timer.merge(fmat_timer);
}

void FPSISender::ssIFMat_send(const oc::span<u64> &u_sums) {
  u64 bins_num = u_sums.size();
  PRNG prng(oc::sysRandomSeed());

  /* ---------------------------------------------------------------------------*/
  // step 1: Sender ssIFMat prefix
  /* ---------------------------------------------------------------------------*/
  u64 threshold = fast_pow<u64>(DELTA, METRIC);
  auto prefix_param = IfMatchParamTable::getSelectedParam(threshold + 1);
  u64 prefix_size = prefix_param.first.size();

  vector<block> prefix_keys;
  u64 keys_size = prefix_size * bins_num;
  prefix_keys.reserve(keys_size);

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  for (u64 i = 0; i < bins_num; i++) {
    auto prefixs = set_prefix(u_sums[i], prefix_param.first);
    for (auto prefix : prefixs) {
      block hash_out;
      blake3_hasher_update(&hasher, prefix.data(), prefix.size());
      blake3_hasher_update(&hasher, &i, sizeof(u64));
      blake3_hasher_finalize(&hasher, hash_out.data(), 16);
      blake3_hasher_reset(&hasher);
      prefix_keys.push_back(hash_out);
    }
  }

  spdlog::debug(
      "\t  [send] ssIFMat —— step1 prefix_keys size: {} ; expect size: {}",
      prefix_keys.size(), keys_size);

  /* ---------------------------------------------------------------------------*/
  // step 2: Sender ssIFMat bOPPRF
  /* ---------------------------------------------------------------------------*/
  u64 opprf_size_other;
  coproto::sync_wait(sockets[0].recv(opprf_size_other));
  coproto::sync_wait(sockets[0].send(keys_size));

  RsOpprfReceiver opprf_recv;
  vector<block> r_(keys_size);

  coproto::sync_wait(opprf_recv.receive(opprf_size_other, prefix_keys, r_, prng,
                                        1, sockets[0]));

  spdlog::debug("\t  [send] ssIFMat —— step2 bOPPRF finished!");

  /* ---------------------------------------------------------------------------*/
  // step 3: Sender ssIFMat bOPPRF2
  /* ---------------------------------------------------------------------------*/
  RsOpprfSender opprf_sender;
  vector<u64> t(bins_num);
  prng.get(t.data(), bins_num);
  vector<u64> t_(keys_size);
  for (u64 i = 0; i < bins_num; i++) {
    for (u64 j = 0; j < prefix_size; j++) {
      t_[i * prefix_size + j] = t[i];
    }
  }

  coproto::sync_wait(
      opprf_sender.send(bins_num, r_, oc::span<u64>(t_), prng, 1, sockets[0]));

  spdlog::debug("\t  [send] ssIFMat —— step3 bOPPRF2 finished! keys size: {}, "
                "vals size: {}",
                r_.size(), t_.size());

  /* ---------------------------------------------------------------------------*/
  // step 4: Sender ssIFMat ssPEQT
  /* ---------------------------------------------------------------------------*/
  auto e = Batch_PEQT_send<u64>(t, sockets[0]);
  ee = sync_wait(e);

  spdlog::debug("\t  [send] ssIFMat —— step4 ssPEQT finished!");
}