#include "pis_new/equal.h"

coproto::task<> eq0(coproto::Socket &chl, u64 length, Triples &triples,
                    BitVector &in0, BitVector &res0) {
  u64 lengthLevel = log2ceil(length);
  u64 curLength = length;
  u64 n = in0.size() / length;
  res0 = in0;
  for (u64 k = 0; k < lengthLevel; k++) {
    u64 sendLength = curLength / 2;
    u64 nextLength = (curLength + 1) / 2;
    BitVector xa0(sendLength * n);
    BitVector yb0(sendLength * n);
    BitVector xa1(sendLength * n);
    BitVector yb1(sendLength * n);
    for (u64 i = 0; i < n; i++) {
      for (u64 j = 0; j < curLength; j += 2) {
        if (j == curLength - 1) {
          // last bit, ignore
        } else {
          xa0[i * sendLength + j / 2] =
              res0[i * curLength + j] ^ triples.curA();
          yb0[i * sendLength + j / 2] =
              res0[i * curLength + j + 1] ^ triples.curB();
          triples.move(1);
        }
      }
    }
    co_await chl.send(xa0);
    co_await chl.send(yb0);
    co_await chl.recv(xa1);
    co_await chl.recv(yb1);
    triples.move(-n * sendLength);
    for (u64 i = 0; i < n; i++) {
      for (u64 j = 0; j < curLength; j += 2) {
        if (j == curLength - 1) {
          // last bit, copy
          res0[i * nextLength + j / 2] = res0[i * curLength + j];
        } else {
          bool d = xa0[i * sendLength + j / 2] ^ xa1[i * sendLength + j / 2];
          bool e = yb0[i * sendLength + j / 2] ^ yb1[i * sendLength + j / 2];
          res0[i * nextLength + j / 2] = (d & e) ^ (d & triples.curB()) ^
                                         (e & triples.curA()) ^ triples.curC();
          triples.move(1);
        }
      }
    }
    curLength = nextLength;
  }
  res0.resize(n);
}

coproto::task<> eq1(coproto::Socket &chl, u64 length, Triples &triples,
                    BitVector &in1, BitVector &res1) {
  u64 lengthLevel = log2ceil(length);

  u64 curLength = length;
  u64 n = in1.size() / length;
  res1 = in1;
  for (u64 k = 0; k < lengthLevel; k++) {
    u64 sendLength = curLength / 2;
    u64 nextLength = (curLength + 1) / 2;
    BitVector xa0(sendLength * n);
    BitVector yb0(sendLength * n);
    BitVector xa1(sendLength * n);
    BitVector yb1(sendLength * n);
    co_await chl.recv(xa0);
    co_await chl.recv(yb0);
    for (u64 i = 0; i < n; i++) {
      for (u64 j = 0; j < curLength; j += 2) {
        if (j == curLength - 1) {
          // last bit, ignore
        } else {
          xa1[i * sendLength + j / 2] =
              res1[i * curLength + j] ^ triples.curA();
          yb1[i * sendLength + j / 2] =
              res1[i * curLength + j + 1] ^ triples.curB();
          triples.move(1);
        }
      }
    }
    co_await chl.send(xa1);
    co_await chl.send(yb1);
    triples.move(-n * sendLength);
    for (u64 i = 0; i < n; i++) {
      for (u64 j = 0; j < curLength; j += 2) {
        if (j == curLength - 1) {
          // last bit, copy
          res1[i * nextLength + j / 2] = res1[i * curLength + j];
        } else {
          bool d = xa0[i * sendLength + j / 2] ^ xa1[i * sendLength + j / 2];
          bool e = yb0[i * sendLength + j / 2] ^ yb1[i * sendLength + j / 2];
          res1[i * nextLength + j / 2] =
              (d & triples.curB()) ^ (e & triples.curA()) ^ triples.curC();
          triples.move(1);
        }
      }
    }
    curLength = nextLength;
  }
  res1.resize(n);
}

BitVector toBitVector(std::span<u64> data, u64 length) {
  BitVector bv(data.size() * length);
  for (u64 i = 0; i < data.size(); i++) {
    for (u64 j = 0; j < length; j++) {
      bv[i * length + j] = (data[i] >> j) & 1;
    }
  }
  return bv;
}