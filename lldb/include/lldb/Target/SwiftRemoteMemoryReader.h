//===-- SwiftRemoteMemoryReader.h -------------------------------*- C++ -*-===//
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

#ifndef liblldb_SwiftRemoteMemoryReader_h_
#define liblldb_SwiftRemoteMemoryReader_h_

#include "lldb/Target/Process.h"
#include "lldb/Target/SwiftLanguageRuntime.h"
#include "lldb/Target/Target.h"

#include "swift/Remote/MemoryReader.h"

namespace lldb_private {

/// Adapter class which allows the Swift Remote Mirrors library to reflect type
/// information from a remote process.
class LLDBMemoryReader : public swift::remote::MemoryReader {
public:
  LLDBMemoryReader(Process &p, size_t max_read_amount = INT32_MAX);

  virtual ~LLDBMemoryReader();

  bool queryDataLayout(DataLayoutQueryType type, void *inBuffer,
                       void *outBuffer) override;

  swift::remote::RemoteAddress
  getSymbolAddress(const std::string &name) override;

  bool readBytes(swift::remote::RemoteAddress address, uint8_t *dest,
                 uint64_t size) override;

  bool readString(swift::remote::RemoteAddress address,
                  std::string &dest) override;

  void pushLocalBuffer(uint64_t local_buffer, uint64_t local_buffer_size);

  void popLocalBuffer();

private:
  Process &m_process;
  size_t m_max_read_amount;

  uint64_t m_local_buffer = 0;
  uint64_t m_local_buffer_size = 0;
};

} // namespace lldb_private

#endif // liblldb_SwiftRemoteMemoryReader_h_
