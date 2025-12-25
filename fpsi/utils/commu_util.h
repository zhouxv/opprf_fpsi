#pragma once
#include "config.h"

void send_chunk(vector<block> &blks, coproto::Socket &socket);
void recv_chunk(vector<block> &blks, coproto::Socket &socket);

// helper functions for block vector manipulation
vector<block> flattenBlocks(const vector<vector<block>> &blockData);
vector<vector<block>> chunkFixedSizeBlocks(const vector<block> &flatData,
                                           size_t chunk_size);