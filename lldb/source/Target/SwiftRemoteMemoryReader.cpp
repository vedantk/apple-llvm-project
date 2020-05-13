//===-- SwiftRemoteMemoryReader.cpp ---------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#include "lldb/Target/SwiftRemoteMemoryReader.h"
#include "lldb/Utility/Log.h"

namespace lldb_private {

LLDBMemoryReader::LLDBMemoryReader(Process &p, size_t max_read_amount)
    : m_process(p) {
  m_max_read_amount = max_read_amount;
}

LLDBMemoryReader::~LLDBMemoryReader() = default;

bool LLDBMemoryReader::queryDataLayout(DataLayoutQueryType type, void *inBuffer,
                                       void *outBuffer) {
  switch (type) {
  case DLQ_GetPointerSize: {
    auto result = static_cast<uint8_t *>(outBuffer);
    *result = m_process.GetAddressByteSize();
    return true;
  }
  case DLQ_GetSizeSize: {
    auto result = static_cast<uint8_t *>(outBuffer);
    *result = m_process.GetAddressByteSize(); // FIXME: sizeof(size_t)
    return true;
  }
  }
  return false;
}

swift::remote::RemoteAddress
LLDBMemoryReader::getSymbolAddress(const std::string &name) {
  lldbassert(!name.empty());
  if (name.empty())
    return swift::remote::RemoteAddress(nullptr);

  LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
           "[MemoryReader] asked to retrieve the address of symbol {0}", name);

  ConstString name_cs(name.c_str(), name.size());
  SymbolContextList sc_list;
  m_process.GetTarget().GetImages().FindSymbolsWithNameAndType(
      name_cs, lldb::eSymbolTypeAny, sc_list);
  if (!sc_list.GetSize()) {
    LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
             "[MemoryReader] symbol resolution failed {0}", name);
    return swift::remote::RemoteAddress(nullptr);
  }

  SymbolContext sym_ctx;
  // Remove undefined symbols from the list.
  size_t num_sc_matches = sc_list.GetSize();
  if (num_sc_matches > 1) {
    SymbolContextList tmp_sc_list(sc_list);
    sc_list.Clear();
    for (size_t idx = 0; idx < num_sc_matches; idx++) {
      tmp_sc_list.GetContextAtIndex(idx, sym_ctx);
      if (sym_ctx.symbol &&
          sym_ctx.symbol->GetType() != lldb::eSymbolTypeUndefined) {
        sc_list.Append(sym_ctx);
      }
    }
  }
  if (sc_list.GetSize() == 1 && sc_list.GetContextAtIndex(0, sym_ctx)) {
    if (sym_ctx.symbol) {
      auto load_addr = sym_ctx.symbol->GetLoadAddress(&m_process.GetTarget());
      LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
               "[MemoryReader] symbol resolved to 0x%" PRIx64, load_addr);
      return swift::remote::RemoteAddress(load_addr);
    }
  }

  // Empty list, resolution failed.
  if (sc_list.GetSize() == 0) {
    LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
             "[MemoryReader] symbol resoution failed {0}", name);
    return swift::remote::RemoteAddress(nullptr);
  }

  // If there's a single symbol, then we're golden. If there's more than
  // a symbol, then just make sure all of them agree on the value.
  Status error;
  auto sym = sc_list.GetContextAtIndex(0, sym_ctx);
  auto load_addr = sym_ctx.symbol->GetLoadAddress(&m_process.GetTarget());
  uint64_t sym_value = m_process.GetTarget().ReadUnsignedIntegerFromMemory(
      load_addr, false, m_process.GetAddressByteSize(), 0, error);
  for (unsigned i = 1; i < sc_list.GetSize(); ++i) {
    auto other_sym = sc_list.GetContextAtIndex(i, sym_ctx);
    auto other_load_addr =
        sym_ctx.symbol->GetLoadAddress(&m_process.GetTarget());
    uint64_t other_sym_value =
        m_process.GetTarget().ReadUnsignedIntegerFromMemory(
            load_addr, false, m_process.GetAddressByteSize(), 0, error);
    if (sym_value != other_sym_value) {
      LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
               "[MemoryReader] symbol resoution failed {0}", name);
      return swift::remote::RemoteAddress(nullptr);
    }
  }
  LLDB_LOG(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES),
           "[MemoryReader] symbol resolved to {0}", load_addr);
  return swift::remote::RemoteAddress(load_addr);
}

bool LLDBMemoryReader::readBytes(swift::remote::RemoteAddress address,
                                 uint8_t *dest, uint64_t size) {
  if (m_local_buffer) {
    auto addr = address.getAddressData();
    if (addr >= m_local_buffer &&
        addr + size <= m_local_buffer + m_local_buffer_size) {
      // If this crashes, the assumptions stated in
      // GetDynamicTypeAndAddress_Protocol() most likely no longer
      // hold.
      memcpy(dest, (void *)addr, size);
      return true;
    }
  }

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES));

  if (log)
    log->Printf("[MemoryReader] asked to read %" PRIu64
                " bytes at address 0x%" PRIx64,
                size, address.getAddressData());

  if (size > m_max_read_amount) {
    if (log)
      log->Printf("[MemoryReader] memory read exceeds maximum allowed size");
    return false;
  }

  Target &target(m_process.GetTarget());
  Address addr(address.getAddressData());
  Status error;
  if (size > target.ReadMemory(addr, false, dest, size, error)) {
    if (log)
      log->Printf(
          "[MemoryReader] memory read returned fewer bytes than asked for");
    return false;
  }
  if (error.Fail()) {
    if (log)
      log->Printf("[MemoryReader] memory read returned error: %s",
                  error.AsCString());
    return false;
  }

  if (log && log->GetVerbose()) {
    StreamString stream;
    for (uint64_t i = 0; i < size; i++) {
      stream.PutHex8(dest[i]);
      stream.PutChar(' ');
    }
    log->Printf("[MemoryReader] memory read returned data: %s",
                stream.GetData());
  }

  return true;
}

bool LLDBMemoryReader::readString(swift::remote::RemoteAddress address,
                                  std::string &dest) {
  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_TYPES));

  if (log)
    log->Printf(
        "[MemoryReader] asked to read string data at address 0x%" PRIx64,
        address.getAddressData());

  uint32_t read_size = 50 * 1024;
  std::vector<char> storage(read_size, 0);
  Target &target(m_process.GetTarget());
  Address addr(address.getAddressData());
  Status error;
  target.ReadCStringFromMemory(addr, &storage[0], storage.size(), error);
  if (error.Success()) {
    dest.assign(&storage[0]);
    if (log)
      log->Printf("[MemoryReader] memory read returned data: %s", dest.c_str());
    return true;
  } else {
    if (log)
      log->Printf("[MemoryReader] memory read returned error: %s",
                  error.AsCString());
    return false;
  }
}

void LLDBMemoryReader::pushLocalBuffer(uint64_t local_buffer,
                                       uint64_t local_buffer_size) {
  lldbassert(!m_local_buffer);
  m_local_buffer = local_buffer;
  m_local_buffer_size = local_buffer_size;
}

void LLDBMemoryReader::popLocalBuffer() {
  lldbassert(m_local_buffer);
  m_local_buffer = 0;
  m_local_buffer_size = 0;
}

} // namespace lldb_private
