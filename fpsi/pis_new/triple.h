#pragma once
#include "config.h"
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <macoro/task.h>

coproto::task<> triple0(coproto::Socket &chl, BitVector &a0, BitVector &b0,
                        BitVector &c0);

coproto::task<> triple1(coproto::Socket &chl, BitVector &a1, BitVector &b1,
                        BitVector &c1);

struct Triples {
  u64 nTriples;
  BitVector a, b, c;
  bool fake = false;

  u64 curTriple = 0;

  bool eager = false;

  macoro::eager_task<> curTask;

  Triples(u64 nTriples)
      : nTriples(nTriples), a(nTriples), b(nTriples), c(nTriples) {}

  bool curA() { return a[curTriple]; }

  bool curB() { return b[curTriple]; }

  bool curC() { return c[curTriple]; }

  void move(i64 offset) { curTriple += offset; }

  coproto::task<> gen0(coproto::Socket &chl) {
    if (!fake) {
      co_await triple0(chl, a, b, c);
    }
  }

  coproto::task<> gen1(coproto::Socket &chl) {
    if (!fake) {
      co_await triple1(chl, a, b, c);
    }
  }

  void eagerGen0(coproto::Socket &chl) {
    eager = true;
    curTask = std::move(gen0(chl) | macoro::make_eager());
  }

  void eagerGen1(coproto::Socket &chl) {
    eager = true;
    curTask = std::move(gen1(chl) | macoro::make_eager());
  }
};

inline bool block_to_bool(block x) { return x.data()[0] & 1; }
