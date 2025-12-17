#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <vector>

using namespace oc;
using namespace std;

// alias of point
using pt = vector<u64>;

const block CUCKOO_SEED = block(0x12321412412312, 0x64628646482);

/*
Parameters and definitions related to OKVS
*/
const u64 OKVS_LAMBDA = 40;
const double OKVS_EPSILON = 0.1;
const block OKVS_SEED = oc::block(6800382592637124185);

// Some parameters of PAILLIER OKVS
const oc::u32 PAILLIER_KEY_SIZE_IN_BIT = 2048;
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BLOCK =
    ((PAILLIER_KEY_SIZE_IN_BIT * 2) / 128);
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BYTE = PAILLIER_CIPHER_SIZE_IN_BLOCK * 16;