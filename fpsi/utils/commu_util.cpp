#include "commu_util.h"

void send_chunk(vector<block> &blks, coproto::Socket &socket) {
  auto flat_size = blks.size();
  auto deal = flat_size / COMMU_CHUNK_SIZE;
  auto remainder = flat_size % COMMU_CHUNK_SIZE;
  // 前n块
  for (u64 i = 0; i < deal; i++) {
    std::span<block> view(blks.data() + i * COMMU_CHUNK_SIZE, COMMU_CHUNK_SIZE);
    coproto::sync_wait(socket.send(view));
    coproto::sync_wait(socket.flush());
  }
  // 最后一块
  if (remainder != 0) {
    std::span<block> view(blks.data() + deal * COMMU_CHUNK_SIZE, remainder);
    coproto::sync_wait(socket.send(view));
    coproto::sync_wait(socket.flush());
  }
}

void recv_chunk(vector<block> &blks, coproto::Socket &socket) {
  auto flat_size = blks.size();
  auto deal = flat_size / COMMU_CHUNK_SIZE;
  auto remainder = flat_size % COMMU_CHUNK_SIZE;
  // 前n块
  for (u64 i = 0; i < deal; i++) {
    std::span<block> view(blks.data() + i * COMMU_CHUNK_SIZE, COMMU_CHUNK_SIZE);
    coproto::sync_wait(socket.recvResize(view));
    coproto::sync_wait(socket.flush());
  }
  // 最后一块
  if (remainder != 0) {
    std::span<block> view(blks.data() + deal * COMMU_CHUNK_SIZE, remainder);
    coproto::sync_wait(socket.recvResize(view));
    coproto::sync_wait(socket.flush());
  }
}

vector<block> flattenBlocks(const vector<vector<block>> &blockData) {
  // 首先计算总元素数量
  size_t total_size = 0;
  for (const auto &inner_vec : blockData) {
    total_size += inner_vec.size();
  }

  // 预分配足够的内存
  vector<block> result;
  result.reserve(total_size);

  // 逐个向量进行内存拷贝
  for (const auto &inner_vec : blockData) {
    if (!inner_vec.empty()) {
      // 直接使用内存拷贝，避免逐个push_back
      size_t old_size = result.size();
      result.resize(old_size + inner_vec.size());
      memcpy(result.data() + old_size, inner_vec.data(),
             inner_vec.size() * sizeof(block));
    }
  }

  return result;
}

vector<vector<block>> chunkFixedSizeBlocks(const vector<block> &flatData,
                                           size_t chunk_size) {
  assert(chunk_size > 0 && "Chunk size must be positive");
  assert(flatData.size() % chunk_size == 0 &&
         "Data size must be divisible by chunk size");

  vector<vector<block>> result;
  result.reserve(flatData.size() / chunk_size);

  for (size_t i = 0; i < flatData.size(); i += chunk_size) {
    result.emplace_back(flatData.begin() + i,
                        flatData.begin() + i + chunk_size);
  }

  return result;
}
