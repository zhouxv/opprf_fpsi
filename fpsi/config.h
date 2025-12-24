#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <vector>

// usr for print block data
#define FMT_DEPRECATED_OSTREAM 1

using namespace oc;
using namespace std;

// alias of point
using pt = vector<u64>;
using u128 = __uint128_t;

const block CUCKOO_SEED = block(0x12321412412312, 0x64628646482);

/*
Parameters and definitions related to OKVS
*/
const u64 OKVS_LAMBDA = 40;
const double OKVS_EPSILON = 0.1;
const block OKVS_SEED = oc::block(6800382592637124185);

// Rist25519: Points on the Ristretto Prime-Order Elliptic Curve Group
using Rist25519_point = osuCrypto::Sodium::Rist25519;
// A finite field number (scalar) based on Curve25519
using Rist25519_number = osuCrypto::Sodium::Prime25519;

// Some parameters of Rist25519 OKVS
const oc::u64 EC_CIPHER_SIZE_IN_NUMBER = 2;
const Rist25519_point dash(oc::block(70));
const Rist25519_point ZERO_POINT(dash - dash);

const size_t POINT_LENGTH_IN_BYTE = sizeof(Rist25519_point);
using Rist25519_point_in_bytes = std::array<oc::u8, POINT_LENGTH_IN_BYTE>;

// Some parameters of PAILLIER OKVS
const oc::u32 PAILLIER_KEY_SIZE_IN_BIT = 2048;
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BLOCK =
    ((PAILLIER_KEY_SIZE_IN_BIT * 2) / 128);
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BYTE = PAILLIER_CIPHER_SIZE_IN_BLOCK * 16;