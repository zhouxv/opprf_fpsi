#include "config.h"
#include "fpsi_protocol.h"
#include "test.h"

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <ipcl/ipcl.hpp>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include "cmp_fmap/fmap.h"

// usage of command line parser
void printUsage() {
  std::cout
      << "Usage:\n"
      << "  ./main [options]\n\n"
      << "Protocol Selection:\n"
      << "  -p <protocol>    Protocol type (default: 1)\n"
      << "                   1 = FMAP protocol\n"
      << "                   2 = FPSI protocol\n\n"
      << "Protocol Parameters:\n"
      << "  -n <size>        Set size (logarithm), default: 8\n"
      << "                   Input set size = 2^n\n"
      << "  -d <dim>         Dimension of the points, default: 2\n"
      << "  -m <metric>      Distance metric, default: 0\n"
      << "                   0 = L-infinity\n"
      << "                   1 = L1\n"
      << "                   2 = L2\n"
      << "  -delta <value>   Distance threshold, default: 10\n"
      << "                   Supported values: 10, 30, 60, 120, 250\n"
      << "  -i <size>        Intersection size, default: 15\n"
      << "  -fm <type>       Fuzzy mapping variant, default: 1\n"
      << "                   0 = Fig.7 (1,1) DFmap\n"
      << "                   1 = spatial_hash (d,d) DFmap\n\n"
      << "Network Configuration:\n"
      << "  -ip <address>    Server IP address, default: \"127.0.0.1\"\n"
      << "  -port <number>   Server port, default: 1212\n\n"
      << "Test and Debug Options:\n"
      << "  -trait <num>     Number of test trials, default: 1\n"
      << "  -detail          Print detailed timing and communication "
         "breakdown\n"
      << "  -log <level>     Log level, default: 1\n"
      << "                   0 = off\n"
      << "                   1 = info\n"
      << "                   2 = debug\n\n"
      << "Examples:\n"
      << "  ./build/main -p 1 -n 8 -d 2 -delta 10\n"
      << "  ./build/main -p 2 -n 10 -d 5 -m 2 -delta 60 -i 20 -detail -fm 1\n";
}

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
      printUsage();
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
      run_fpsi_protocol_extra(cmd);
      break;
    default:
      spdlog::error("Unknown protocol type", protocol_type);
      printUsage();
    }
    return 0;
  }

  printUsage();

  return 0;
}
