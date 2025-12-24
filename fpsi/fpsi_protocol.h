#pragma once
#include "config.h"
#include <cryptoTools/Common/CLP.h>

enum class Role {
  Recv,  // receiver
  Sender // sender
};

void run_fmap_protocol(const CLP &cmd);

std::pair<double, double>
run_fmap_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                  const u64 DELTA, const u64 INTERSECTION_SIZE, const string IP,
                  const u64 PORT, const bool FM_OLD, const bool PTS_SAME,
                  const bool DETAILED, const bool FAKE);

void run_fpsi_protocol(const CLP &cmd);

std::pair<double, double>
run_fpsi_protocol(const u64 PT_NUM, const u64 DIM, const u64 METRIC,
                  const u64 DELTA, const u64 INTERSECTION_SIZE, const string IP,
                  const u64 PORT, const bool PTS_SAME, const bool DETAILED,
                  const bool FAKE);
