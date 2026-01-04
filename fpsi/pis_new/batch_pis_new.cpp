#include "pis_new/batch_pis_new.h"
/*
 compute the split index of vector, reuse in PIS
 suppose eles_size is 2^⌈log 𝜇⌉− 1
 Example:
   eles_size = 8
   return [
     [1,3,5,7],    // index with bit 0 set
     [2,3,6,7],    // index with bit 1 set
     [4,5,6,7]     // index with bit 2 set
   ]
*/
vector<vector<u64>> compute_split_index(const u64 eles_size) {
  // check eles_size is power of 2
  assert((eles_size & (eles_size - 1)) == 0);
  u64 vector_num = log2(eles_size);

  vector<vector<u64>> res(vector_num);

  // prepare bit mask : 0b001, 0b010, 0b100, ...
  vector<u64> mask(vector_num);
  for (u64 i = 0; i < vector_num; i++) {
    mask[i] = 1 << i;
  }

  // iterate over all elements
  for (u64 i = 0; i < eles_size; i++) {
    // check whether the k-th bit of index i in binary representation is 1
    for (u64 j = 0; j < vector_num; j++) {
      if ((i & mask[j]) != 0) {
        res[j].push_back(i);
      }
    }
  }

  return res;
}