//===-- StringPrinter.cpp ----------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/DataFormatters/StringPrinter.h"

#include "lldb/Core/Debugger.h"
#include "lldb/Core/ValueObject.h"
#include "lldb/Target/Language.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/Status.h"

#include "llvm/Support/ConvertUTF.h"

#include <ctype.h>
#include <locale>
#include <memory>

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::formatters;
using GetPrintableElementType = StringPrinter::GetPrintableElementType;
using StringElementType = StringPrinter::StringElementType;

/// StringPrinterBufferPointer is basically a unique_ptr specialized for the
/// needs of this file: the buffer pointer doesn't /have/ to be heap-allocated,
/// and the convenience constructors make it easier to create string chunks.
struct StringPrinterBufferPointer {
public:
  using Deleter = std::function<void(const uint8_t *)>;

  StringPrinterBufferPointer(std::nullptr_t ptr)
      : m_data(nullptr), m_size(0), m_deleter() {}

  StringPrinterBufferPointer(const uint8_t *bytes, size_t size,
                             Deleter deleter = nullptr)
      : m_data(bytes), m_size(size), m_deleter(deleter) {}

  StringPrinterBufferPointer(const char *bytes, size_t size,
                             Deleter deleter = nullptr)
      : m_data(reinterpret_cast<const uint8_t *>(bytes)), m_size(size),
        m_deleter(deleter) {}

  StringPrinterBufferPointer(StringPrinterBufferPointer &&rhs)
      : m_data(rhs.m_data), m_size(rhs.m_size), m_deleter(rhs.m_deleter) {
    rhs.m_data = nullptr;
  }

  ~StringPrinterBufferPointer() {
    if (m_data && m_deleter)
      m_deleter(m_data);
    m_data = nullptr;
  }

  const uint8_t *GetBytes() const { return m_data; }

  size_t GetSize() const { return m_size; }

  StringPrinterBufferPointer &operator=(StringPrinterBufferPointer &&rhs) {
    if (m_data && m_deleter)
      m_deleter(m_data);
    m_data = rhs.m_data;
    m_size = rhs.m_size;
    m_deleter = rhs.m_deleter;
    rhs.m_data = nullptr;
    return *this;
  }

private:
  DISALLOW_COPY_AND_ASSIGN(StringPrinterBufferPointer);

  const uint8_t *m_data;
  size_t m_size;
  Deleter m_deleter;
};

using EscapingHelper =
    std::function<StringPrinterBufferPointer(uint8_t *, uint8_t *, uint8_t *&)>;

// we define this for all values of type but only implement it for those we
// care about that's good because we get linker errors for any unsupported type
template <StringElementType type>
static StringPrinterBufferPointer
GetPrintableImpl(uint8_t *buffer, uint8_t *buffer_end, uint8_t *&next,
                 StringPrinter::EscapeStyle escape_style);

// Mimic isprint() for Unicode codepoints.
static bool isprint32(char32_t codepoint) {
  if (codepoint <= 0x1F || codepoint == 0x7F) // C0
  {
    return false;
  }
  if (codepoint >= 0x80 && codepoint <= 0x9F) // C1
  {
    return false;
  }
  if (codepoint == 0x2028 || codepoint == 0x2029) // line/paragraph separators
  {
    return false;
  }
  if (codepoint == 0x200E || codepoint == 0x200F ||
      (codepoint >= 0x202A &&
       codepoint <= 0x202E)) // bidirectional text control
  {
    return false;
  }
  if (codepoint >= 0xFFF9 &&
      codepoint <= 0xFFFF) // interlinears and generally specials
  {
    return false;
  }
  return true;
}

StringPrinterBufferPointer
attemptASCIIEscape(char32_t c, StringPrinter::EscapeStyle escape_style) {
  const bool is_swift_escape_style =
      escape_style == StringPrinter::EscapeStyle::Swift;
  switch (c) {
  case 0:
    return {"\\0", 2};
  case '\a':
    return {"\\a", 2};
  case '\b':
    if (is_swift_escape_style)
      return nullptr;
    return {"\\b", 2};
  case '\f':
    if (is_swift_escape_style)
      return nullptr;
    return {"\\f", 2};
  case '\n':
    return {"\\n", 2};
  case '\r':
    return {"\\r", 2};
  case '\t':
    return {"\\t", 2};
  case '\v':
    if (is_swift_escape_style)
      return nullptr;
    return {"\\v", 2};
  case '\"':
    return {"\\\"", 2};
  case '\'':
    if (!is_swift_escape_style)
      return nullptr;
    return {"\\'", 2};
  case '\\':
    return {"\\\\", 2};
  }
  return nullptr;
}

template <>
StringPrinterBufferPointer
GetPrintableImpl<StringElementType::ASCII>(
    uint8_t *buffer, uint8_t *buffer_end, uint8_t *&next,
    StringPrinter::EscapeStyle escape_style) {
  // The ASCII helper always advances 1 byte at a time.
  next = buffer + 1;

  StringPrinterBufferPointer retval = attemptASCIIEscape(*buffer, escape_style);
  if (retval.GetSize())
    return retval;
  if (isprint(*buffer))
    return {buffer, 1};

  unsigned escaped_len;
  const unsigned max_buffer_size = 7;
  uint8_t *data = new uint8_t[max_buffer_size];
  switch (escape_style) {
  case StringPrinter::EscapeStyle::CXX:
    // Prints 4 characters, then a \0 terminator.
    escaped_len = sprintf((char *)data, "\\x%02x", *buffer);
    break;
  case StringPrinter::EscapeStyle::Swift:
    // Prints up to 6 characters, then a \0 terminator.
    escaped_len = sprintf((char *)data, "\\u{%x}", *buffer);
    break;
  }
  lldbassert(escaped_len > 0 && "unknown string escape style");
  return {data, escaped_len, [](const uint8_t *c) { delete[] c; }};
}

static char32_t ConvertUTF8ToCodePoint(unsigned char c0, unsigned char c1) {
  return (c0 - 192) * 64 + (c1 - 128);
}
static char32_t ConvertUTF8ToCodePoint(unsigned char c0, unsigned char c1,
                                       unsigned char c2) {
  return (c0 - 224) * 4096 + (c1 - 128) * 64 + (c2 - 128);
}
static char32_t ConvertUTF8ToCodePoint(unsigned char c0, unsigned char c1,
                                       unsigned char c2, unsigned char c3) {
  return (c0 - 240) * 262144 + (c2 - 128) * 4096 + (c2 - 128) * 64 + (c3 - 128);
}

template <>
StringPrinterBufferPointer
GetPrintableImpl<StringElementType::UTF8>(
    uint8_t *buffer, uint8_t *buffer_end, uint8_t *&next,
    StringPrinter::EscapeStyle escape_style) {
  const unsigned utf8_encoded_len = llvm::getNumBytesForUTF8(*buffer);

  // If the utf8 encoded length is invalid, or if there aren't enough bytes to
  // print, this is some kind of corrupted string.
  if (utf8_encoded_len == 0 || utf8_encoded_len > 4)
    return nullptr;
  if ((buffer_end - buffer) < utf8_encoded_len)
    // There's no room in the buffer for the utf8 sequence.
    return nullptr;

  char32_t codepoint = 0;
  switch (utf8_encoded_len) {
  case 1:
    // this is just an ASCII byte - ask ASCII
    return GetPrintableImpl<StringElementType::ASCII>(buffer, buffer_end, next,
                                                      escape_style);
  case 2:
    codepoint = ConvertUTF8ToCodePoint((unsigned char)*buffer,
                                       (unsigned char)*(buffer + 1));
    break;
  case 3:
    codepoint = ConvertUTF8ToCodePoint((unsigned char)*buffer,
                                       (unsigned char)*(buffer + 1),
                                       (unsigned char)*(buffer + 2));
    break;
  case 4:
    codepoint = ConvertUTF8ToCodePoint(
        (unsigned char)*buffer, (unsigned char)*(buffer + 1),
        (unsigned char)*(buffer + 2), (unsigned char)*(buffer + 3));
    break;
  }

  // We couldn't figure out how to print this codepoint.
  if (!codepoint)
    return nullptr;

  // The UTF8 helper always advances by the utf8 encoded length.
  next = buffer + utf8_encoded_len;
  StringPrinterBufferPointer retval =
      attemptASCIIEscape(codepoint, escape_style);
  if (retval.GetSize())
    return retval;
  if (isprint32(codepoint))
    return {buffer, utf8_encoded_len};

  unsigned escaped_len;
  const unsigned max_buffer_size = 15;
  uint8_t *data = new uint8_t[max_buffer_size];
  switch (escape_style) {
  case StringPrinter::EscapeStyle::CXX:
    // Prints 10 characters, then a \0 terminator.
    escaped_len = sprintf((char *)data, "\\U%08x", (unsigned)codepoint);
    break;
  case StringPrinter::EscapeStyle::Swift:
    // Prints up to 14 characters, then a \0 terminator.
    escaped_len = sprintf((char *)data, "\\u{%x}", (unsigned)codepoint);
    break;
  }
  lldbassert(escaped_len > 0 && "unknown string escape style");
  return {data, escaped_len, [](const uint8_t *c) { delete[] c; }};
}

// Given a sequence of bytes, this function returns: a sequence of bytes to
// actually print out + a length the following unscanned position of the buffer
// is in next
static StringPrinterBufferPointer
GetPrintable(StringElementType type, uint8_t *buffer, uint8_t *buffer_end,
             uint8_t *&next, StringPrinter::EscapeStyle escape_style) {
  if (!buffer || buffer >= buffer_end)
    return {nullptr};

  switch (type) {
  case StringElementType::ASCII:
    return GetPrintableImpl<StringElementType::ASCII>(
        buffer, buffer_end, next, escape_style);
  case StringElementType::UTF8:
    return GetPrintableImpl<StringElementType::UTF8>(
        buffer, buffer_end, next, escape_style);
  default:
    return {nullptr};
  }
}

static EscapingHelper
GetDefaultEscapingHelper(GetPrintableElementType elem_type,
                         StringPrinter::EscapeStyle escape_style) {
  switch (elem_type) {
  case GetPrintableElementType::UTF8:
    return [escape_style](uint8_t *buffer, uint8_t *buffer_end,
                          uint8_t *&next) -> StringPrinterBufferPointer {
      return GetPrintable(StringElementType::UTF8, buffer, buffer_end, next,
                          escape_style);
    };
  case GetPrintableElementType::ASCII:
    return [escape_style](uint8_t *buffer, uint8_t *buffer_end,
                          uint8_t *&next) -> StringPrinterBufferPointer {
      return GetPrintable(StringElementType::ASCII, buffer, buffer_end, next,
                          escape_style);
    };
  }
  llvm_unreachable("bad element type");
}

// use this call if you already have an LLDB-side buffer for the data
template <typename SourceDataType>
static bool DumpUTFBufferToStream(
    llvm::ConversionResult (*ConvertFunction)(const SourceDataType **,
                                              const SourceDataType *,
                                              llvm::UTF8 **, llvm::UTF8 *,
                                              llvm::ConversionFlags),
    const StringPrinter::ReadBufferAndDumpToStreamOptions &dump_options) {
  Stream &stream(*dump_options.GetStream());
  if (dump_options.GetPrefixToken() != nullptr)
    stream.Printf("%s", dump_options.GetPrefixToken());
  if (dump_options.GetQuote() != 0)
    stream.Printf("%c", dump_options.GetQuote());
  auto data(dump_options.GetData());
  auto source_size(dump_options.GetSourceSize());
  if (data.GetByteSize() && data.GetDataStart() && data.GetDataEnd()) {
    const int bufferSPSize = data.GetByteSize();
    if (dump_options.GetSourceSize() == 0) {
      const int origin_encoding = 8 * sizeof(SourceDataType);
      source_size = bufferSPSize / (origin_encoding / 4);
    }

    const SourceDataType *data_ptr =
        (const SourceDataType *)data.GetDataStart();
    const SourceDataType *data_end_ptr = data_ptr + source_size;

    const bool zero_is_terminator = dump_options.GetBinaryZeroIsTerminator();

    if (zero_is_terminator) {
      while (data_ptr < data_end_ptr) {
        if (!*data_ptr) {
          data_end_ptr = data_ptr;
          break;
        }
        data_ptr++;
      }

      data_ptr = (const SourceDataType *)data.GetDataStart();
    }

    lldb::DataBufferSP utf8_data_buffer_sp;
    llvm::UTF8 *utf8_data_ptr = nullptr;
    llvm::UTF8 *utf8_data_end_ptr = nullptr;

    if (ConvertFunction) {
      utf8_data_buffer_sp =
          std::make_shared<DataBufferHeap>(4 * bufferSPSize, 0);
      utf8_data_ptr = (llvm::UTF8 *)utf8_data_buffer_sp->GetBytes();
      utf8_data_end_ptr = utf8_data_ptr + utf8_data_buffer_sp->GetByteSize();
      ConvertFunction(&data_ptr, data_end_ptr, &utf8_data_ptr,
                      utf8_data_end_ptr, llvm::lenientConversion);
      if (!zero_is_terminator)
        utf8_data_end_ptr = utf8_data_ptr;
      // needed because the ConvertFunction will change the value of the
      // data_ptr.
      utf8_data_ptr =
          (llvm::UTF8 *)utf8_data_buffer_sp->GetBytes();
    } else {
      // just copy the pointers - the cast is necessary to make the compiler
      // happy but this should only happen if we are reading UTF8 data
      utf8_data_ptr = const_cast<llvm::UTF8 *>(
          reinterpret_cast<const llvm::UTF8 *>(data_ptr));
      utf8_data_end_ptr = const_cast<llvm::UTF8 *>(
          reinterpret_cast<const llvm::UTF8 *>(data_end_ptr));
    }

    const bool escape_non_printables = dump_options.GetEscapeNonPrintables();
    EscapingHelper escaping_callback;
    if (escape_non_printables)
      escaping_callback = GetDefaultEscapingHelper(
          GetPrintableElementType::UTF8, dump_options.GetEscapeStyle());

    // since we tend to accept partial data (and even partially malformed data)
    // we might end up with no NULL terminator before the end_ptr hence we need
    // to take a slower route and ensure we stay within boundaries
    for (; utf8_data_ptr < utf8_data_end_ptr;) {
      if (zero_is_terminator && !*utf8_data_ptr)
        break;

      if (escape_non_printables) {
        uint8_t *next_data = nullptr;
        auto printable =
            escaping_callback(utf8_data_ptr, utf8_data_end_ptr, next_data);
        auto printable_bytes = printable.GetBytes();
        auto printable_size = printable.GetSize();

        // We failed to figure out how to print this string.
        if (!printable_bytes || !next_data)
          return false;

        for (unsigned c = 0; c < printable_size; c++)
          stream.Printf("%c", *(printable_bytes + c));
        utf8_data_ptr = (uint8_t *)next_data;
      } else {
        stream.Printf("%c", *utf8_data_ptr);
        utf8_data_ptr++;
      }
    }
  }
  if (dump_options.GetQuote() != 0)
    stream.Printf("%c", dump_options.GetQuote());
  if (dump_options.GetSuffixToken() != nullptr)
    stream.Printf("%s", dump_options.GetSuffixToken());
  if (dump_options.GetIsTruncated())
    stream.Printf("...");
  return true;
}

lldb_private::formatters::StringPrinter::ReadStringAndDumpToStreamOptions::
    ReadStringAndDumpToStreamOptions(ValueObject &valobj)
    : ReadStringAndDumpToStreamOptions() {
  SetEscapeNonPrintables(
      valobj.GetTargetSP()->GetDebugger().GetEscapeNonPrintables());
}

lldb_private::formatters::StringPrinter::ReadBufferAndDumpToStreamOptions::
    ReadBufferAndDumpToStreamOptions(ValueObject &valobj)
    : ReadBufferAndDumpToStreamOptions() {
  SetEscapeNonPrintables(
      valobj.GetTargetSP()->GetDebugger().GetEscapeNonPrintables());
}

lldb_private::formatters::StringPrinter::ReadBufferAndDumpToStreamOptions::
    ReadBufferAndDumpToStreamOptions(
        const ReadStringAndDumpToStreamOptions &options)
    : ReadBufferAndDumpToStreamOptions() {
  SetStream(options.GetStream());
  SetPrefixToken(options.GetPrefixToken());
  SetSuffixToken(options.GetSuffixToken());
  SetQuote(options.GetQuote());
  SetEscapeNonPrintables(options.GetEscapeNonPrintables());
  SetBinaryZeroIsTerminator(options.GetBinaryZeroIsTerminator());
  SetEscapeStyle(options.GetEscapeStyle());
}

namespace lldb_private {

namespace formatters {

// FIXME: In practice, do we ever prefer ASCII-only formatting over UTF8
// formatting? The NSString formatter is the only one that makes a distinction
// between the two: if it doesn't need to, we can simply delete all this
// duplicated ASCII-specific code.
template <>
bool StringPrinter::ReadStringAndDumpToStream<StringElementType::ASCII>(
    const ReadStringAndDumpToStreamOptions &options) {
  assert(options.GetStream() && "need a Stream to print the string to");
  Status my_error;

  ProcessSP process_sp(options.GetProcessSP());

  if (process_sp.get() == nullptr || options.GetLocation() == 0)
    return false;

  size_t size;
  const auto max_size = process_sp->GetTarget().GetMaximumSizeOfStringSummary();
  bool is_truncated = false;

  if (options.GetSourceSize() == 0)
    size = max_size;
  else if (!options.GetIgnoreMaxLength()) {
    size = options.GetSourceSize();
    if (size > max_size) {
      size = max_size;
      is_truncated = true;
    }
  } else
    size = options.GetSourceSize();

  lldb::DataBufferSP buffer_sp(new DataBufferHeap(size, 0));

  process_sp->ReadCStringFromMemory(
      options.GetLocation(), (char *)buffer_sp->GetBytes(), size, my_error);

  if (my_error.Fail())
    return false;

  const char *prefix_token = options.GetPrefixToken();
  char quote = options.GetQuote();

  if (prefix_token != nullptr)
    options.GetStream()->Printf("%s%c", prefix_token, quote);
  else if (quote != 0)
    options.GetStream()->Printf("%c", quote);

  uint8_t *data_end = buffer_sp->GetBytes() + buffer_sp->GetByteSize();

  const bool escape_non_printables = options.GetEscapeNonPrintables();
  EscapingHelper escaping_callback;
  if (escape_non_printables)
    escaping_callback = GetDefaultEscapingHelper(GetPrintableElementType::ASCII,
                                                 options.GetEscapeStyle());

  // since we tend to accept partial data (and even partially malformed data)
  // we might end up with no NULL terminator before the end_ptr hence we need
  // to take a slower route and ensure we stay within boundaries
  for (uint8_t *data = buffer_sp->GetBytes(); *data && (data < data_end);) {
    if (escape_non_printables) {
      uint8_t *next_data = nullptr;
      auto printable = escaping_callback(data, data_end, next_data);
      auto printable_bytes = printable.GetBytes();
      auto printable_size = printable.GetSize();

      // We failed to figure out how to print this string.
      if (!printable_bytes || !next_data)
        return false;

      for (unsigned c = 0; c < printable_size; c++)
        options.GetStream()->Printf("%c", *(printable_bytes + c));
      data = (uint8_t *)next_data;
    } else {
      options.GetStream()->Printf("%c", *data);
      data++;
    }
  }

  const char *suffix_token = options.GetSuffixToken();

  if (suffix_token != nullptr)
    options.GetStream()->Printf("%c%s", quote, suffix_token);
  else if (quote != 0)
    options.GetStream()->Printf("%c", quote);

  if (is_truncated)
    options.GetStream()->Printf("...");

  return true;
}

template <typename SourceDataType>
static bool ReadUTFBufferAndDumpToStream(
    const StringPrinter::ReadStringAndDumpToStreamOptions &options,
    llvm::ConversionResult (*ConvertFunction)(const SourceDataType **,
                                              const SourceDataType *,
                                              llvm::UTF8 **, llvm::UTF8 *,
                                              llvm::ConversionFlags)) {
  assert(options.GetStream() && "need a Stream to print the string to");

  if (options.GetLocation() == 0 ||
      options.GetLocation() == LLDB_INVALID_ADDRESS)
    return false;

  lldb::ProcessSP process_sp(options.GetProcessSP());

  if (!process_sp)
    return false;

  const int type_width = sizeof(SourceDataType);
  const int origin_encoding = 8 * type_width;
  if (origin_encoding != 8 && origin_encoding != 16 && origin_encoding != 32)
    return false;
  // if not UTF8, I need a conversion function to return proper UTF8
  if (origin_encoding != 8 && !ConvertFunction)
    return false;

  if (!options.GetStream())
    return false;

  uint32_t sourceSize;
  bool needs_zero_terminator = options.GetNeedsZeroTermination();

  bool is_truncated = false;
  const auto max_size = process_sp->GetTarget().GetMaximumSizeOfStringSummary();

  if (options.HasSourceSize()) {
    sourceSize = options.GetSourceSize();
    if (!options.GetIgnoreMaxLength()) {
      if (sourceSize > max_size) {
        sourceSize = max_size;
        is_truncated = true;
      }
    }
  } else {
    sourceSize = max_size;
    needs_zero_terminator = true;
  }

  const int bufferSPSize = sourceSize * type_width;

  lldb::DataBufferSP buffer_sp(new DataBufferHeap(bufferSPSize, 0));

  // Check if we got bytes. We never get any bytes if we have an empty
  // string, but we still continue so that we end up actually printing
  // an empty string ("").
  if (sourceSize != 0 && !buffer_sp->GetBytes())
    return false;

  Status error;
  char *buffer = reinterpret_cast<char *>(buffer_sp->GetBytes());

  if (needs_zero_terminator)
    process_sp->ReadStringFromMemory(options.GetLocation(), buffer,
                                     bufferSPSize, error, type_width);
  else
    process_sp->ReadMemoryFromInferior(options.GetLocation(),
                                       (char *)buffer_sp->GetBytes(),
                                       bufferSPSize, error);

  if (error.Fail()) {
    options.GetStream()->Printf("unable to read data");
    return true;
  }

  DataExtractor data(buffer_sp, process_sp->GetByteOrder(),
                     process_sp->GetAddressByteSize());

  StringPrinter::ReadBufferAndDumpToStreamOptions dump_options(options);
  dump_options.SetData(data);
  dump_options.SetSourceSize(sourceSize);
  dump_options.SetIsTruncated(is_truncated);

  return DumpUTFBufferToStream(ConvertFunction, dump_options);
}

template <>
bool StringPrinter::ReadStringAndDumpToStream<StringElementType::UTF8>(
    const ReadStringAndDumpToStreamOptions &options) {
  return ReadUTFBufferAndDumpToStream<llvm::UTF8>(options, nullptr);
}

template <>
bool StringPrinter::ReadStringAndDumpToStream<StringElementType::UTF16>(
    const ReadStringAndDumpToStreamOptions &options) {
  return ReadUTFBufferAndDumpToStream<llvm::UTF16>(options,
                                                   llvm::ConvertUTF16toUTF8);
}

template <>
bool StringPrinter::ReadStringAndDumpToStream<StringElementType::UTF32>(
    const ReadStringAndDumpToStreamOptions &options) {
  return ReadUTFBufferAndDumpToStream<llvm::UTF32>(options,
                                                   llvm::ConvertUTF32toUTF8);
}

template <>
bool StringPrinter::ReadBufferAndDumpToStream<StringElementType::UTF8>(
    const ReadBufferAndDumpToStreamOptions &options) {
  assert(options.GetStream() && "need a Stream to print the string to");

  return DumpUTFBufferToStream<llvm::UTF8>(nullptr, options);
}

template <>
bool StringPrinter::ReadBufferAndDumpToStream<StringElementType::ASCII>(
    const ReadBufferAndDumpToStreamOptions &options) {
  // treat ASCII the same as UTF8
  // FIXME: can we optimize ASCII some more?
  return ReadBufferAndDumpToStream<StringElementType::UTF8>(options);
}

template <>
bool StringPrinter::ReadBufferAndDumpToStream<StringElementType::UTF16>(
    const ReadBufferAndDumpToStreamOptions &options) {
  assert(options.GetStream() && "need a Stream to print the string to");

  return DumpUTFBufferToStream(llvm::ConvertUTF16toUTF8, options);
}

template <>
bool StringPrinter::ReadBufferAndDumpToStream<StringElementType::UTF32>(
    const ReadBufferAndDumpToStreamOptions &options) {
  assert(options.GetStream() && "need a Stream to print the string to");

  return DumpUTFBufferToStream(llvm::ConvertUTF32toUTF8, options);
}

} // namespace formatters

} // namespace lldb_private
