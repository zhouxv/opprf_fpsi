#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <vector>

using namespace oc;
using namespace std;

// alias of point
using pt = vector<u64>;

const block CUCKOO_SEED = block(0x12321412412312, 0x64628646482);