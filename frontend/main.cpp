#include "config.h"
#include "fpsi_protocol.h"
#include "test.h"

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <ipcl/ipcl.hpp>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  /*
  spdlog logs setting
  0: no log
  1: info
  2: debug
  */
  //  Set up logs
  auto log_level = cmd.getOr<u64>("log", 1);

  // spdlog::set_pattern("[%l] %v");
  spdlog::set_pattern("%v");
  switch (log_level) {
  case 0:
    spdlog::set_level(spdlog::level::off);
    break;
  case 1:
    spdlog::set_level(spdlog::level::info);
    break;
  case 2:
    spdlog::set_level(spdlog::level::debug);
    break;
  default:
    spdlog::set_level(spdlog::level::info);
  }

  /*
  Unit tests
  1: test opprf
  2: test vole noisy
  */
  if (cmd.isSet("t")) {
    const u64 test_type = cmd.getOr("t", 0);
    switch (test_type) {
    case 1:
      test_opprf(cmd);
      break;
    case 2:
      test_pailliar(cmd);
      break;
    case 3:
      test_batch_peqt(cmd);
      break;
    case 4:
      test_vole_noisy(cmd);
      break;
    case 5:
      test_vole_slient(cmd);
      break;
    case 6:
      test_prefix_param(cmd);
      break;
    case 7:
      test_data_convert(cmd);
      break;
    default:
      spdlog::error("Unknown test type", test_type);
    }
    return 0;
  }

  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 1);
    switch (protocol_type) {
    case 1:
      run_fmap_protocol(cmd);
      break;
    case 2:
      run_fpsi_protocol(cmd);
      break;
    default:
      spdlog::error("Unknown protocol type", protocol_type);
    }
  }

  return 0;
}
