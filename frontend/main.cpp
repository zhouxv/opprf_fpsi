#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <string>

#include "test.h"

using namespace osuCrypto;

void usage() {
  std::cout << "\nUsage: ./fpsi -p <protocol_type> [options]\n"
            << "Available protocols:\n"
            << "  1: Low Dimension Protocol\n"
            << "  2: High Dimension Protocol\n"
            << "  3: Test Low Dimension Protocol\n"
            << "  4: Test High Dimension Protocol\n"
            << "Options:\n"
            << "  -log <level> : Set log level (0: off, 1: info, 2: debug)\n";
}

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

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
  case 3:
    spdlog::set_level(spdlog::level::debug);
    break;
  default:
    spdlog::set_level(spdlog::level::info);
  }

  // Select the executed protocol
  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 0);
    switch (protocol_type) {
    // case 1:
    //   test_linf_protocol(cmd);
    //   break;
    // case 2:
    //   test_lp_protocol(cmd);
    //   break;
    default:
      spdlog::error("Unknown protocol type", protocol_type);
      usage();
    }
    return 0;
  }

  // Select the executed protocol
  if (cmd.isSet("t")) {
    const u64 test_type = cmd.getOr("t", 0);
    switch (test_type) {
    case 1:
      test_opprf(cmd);
      break;
    case 2:
      test_Vole_Noisy(cmd);
      break;
    default:
      spdlog::error("Unknown test type", test_type);
      usage();
    }
    return 0;
  }

  return 0;
}