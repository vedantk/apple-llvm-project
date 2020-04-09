//===-- StringPrinterTests.cpp ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/DataFormatters/StringPrinter.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Endian.h"
#include "lldb/Utility/StreamString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
#include "gtest/gtest.h"

using namespace lldb;
using namespace lldb_private;
using lldb_private::formatters::StringPrinter;
using llvm::StringRef;

#define QUOTE(x) "\"" x "\""

/// Dump out "name: { <contents of str> }".
static void dumpStr(StringRef name, StringRef str) {
  llvm::errs() << name << ": { ";
  for (char c : str)
    llvm::errs() << c << " ";
  llvm::errs() << "}\n";
}

/// Format \p input according to the options specified in the template params,
/// then check whether the result is equal to \p reference. If not, dump the
/// expeted vs. actual results.
template <StringPrinter::StringElementType elem_ty,
          StringPrinter::EscapeStyle escape_style>
static bool isFormatCorrect(StringRef input, StringRef reference) {
  StreamString out;
  StringPrinter::ReadBufferAndDumpToStreamOptions opts;
  opts.SetStream(&out);
  opts.SetSourceSize(input.size());
  opts.SetNeedsZeroTermination(true);
  opts.SetEscapeNonPrintables(true);
  opts.SetIgnoreMaxLength(false);
  opts.SetEscapeStyle(escape_style);
  DataExtractor extractor(input.data(), input.size(),
                          endian::InlHostByteOrder(), sizeof(void *));
  opts.SetData(extractor);
  const bool success = StringPrinter::ReadBufferAndDumpToStream<elem_ty>(opts);
  const bool matches = out.GetString() == reference;
  if (!success || !matches) {
    dumpStr("expected", reference);
    dumpStr(" but got", out.GetString());
  }
  return matches;
}

// The "StringElementType::ASCII + EscapeStyle::CXX" combination is not tested
// because it probably should not be supported (see FIXME in StringPrinter.cpp),
// and because it's implemented by calling into the UTF8 logic anyway.

// Test UTF8 formatting for C++.
TEST(StringPrinterTests, CxxUTF8) {
  auto matches = [](StringRef str, StringRef reference) {
    return isFormatCorrect<StringPrinter::StringElementType::UTF8,
                           StringPrinter::EscapeStyle::CXX>(str, reference);
  };

  // Special escapes.
  EXPECT_TRUE(matches({"\0", 1}, QUOTE("")));
  EXPECT_TRUE(matches("\a", QUOTE("\\a")));
  EXPECT_TRUE(matches("\b", QUOTE("\\b")));
  EXPECT_TRUE(matches("\f", QUOTE("\\f")));
  EXPECT_TRUE(matches("\n", QUOTE("\\n")));
  EXPECT_TRUE(matches("\r", QUOTE("\\r")));
  EXPECT_TRUE(matches("\t", QUOTE("\\t")));
  EXPECT_TRUE(matches("\v", QUOTE("\\v")));
  EXPECT_TRUE(matches("\"", QUOTE("\\\"")));
  EXPECT_TRUE(matches("\'", QUOTE("'")));
  EXPECT_TRUE(matches("\\", QUOTE("\\\\")));

  // Printable characters.
  EXPECT_TRUE(matches("'", QUOTE("'")));
  EXPECT_TRUE(matches("a", QUOTE("a")));
  EXPECT_TRUE(matches("Z", QUOTE("Z")));
  EXPECT_TRUE(matches("🥑", QUOTE("🥑")));

  // Octal (\nnn), hex (\xnn), extended octal (\unnnn or \Unnnnnnnn).
  EXPECT_TRUE(matches("\uD55C", QUOTE("한")));
  EXPECT_TRUE(matches("\U00010348", QUOTE("𐍈")));

  // FIXME: These strings are all rejected, but shouldn't be AFAICT. LLDB finds
  // that these are not valid utf8 sequences, but that's OK, the raw values
  // should still be printed out.
  EXPECT_FALSE(matches("\376", QUOTE("\\xfe"))); // \376 is 254 in decimal.
  EXPECT_FALSE(matches("\xfe", QUOTE("\\xfe"))); // \xfe is 254 in decimal.
}

// Test UTF8 formatting for Swift.
TEST(StringPrinterTests, SwiftUTF8) {
  auto matches = [](StringRef str, StringRef reference) {
    return isFormatCorrect<StringPrinter::StringElementType::UTF8,
                           StringPrinter::EscapeStyle::Swift>(str, reference);
  };

  // Special escapes.
  EXPECT_TRUE(matches({"\0", 1}, QUOTE("")));
  EXPECT_TRUE(matches("\a", QUOTE("\\a")));
  EXPECT_TRUE(matches("\b", QUOTE("\\u{8}")));
  EXPECT_TRUE(matches("\f", QUOTE("\\u{c}")));
  EXPECT_TRUE(matches("\n", QUOTE("\\n")));
  EXPECT_TRUE(matches("\r", QUOTE("\\r")));
  EXPECT_TRUE(matches("\t", QUOTE("\\t")));
  EXPECT_TRUE(matches("\v", QUOTE("\\u{b}")));
  EXPECT_TRUE(matches("\"", QUOTE("\\\"")));
  EXPECT_TRUE(matches("\'", QUOTE("\\'")));
  EXPECT_TRUE(matches("\\", QUOTE("\\\\")));

  // Printable characters.
  EXPECT_TRUE(matches("'", QUOTE("\\'")));
  EXPECT_TRUE(matches("a", QUOTE("a")));
  EXPECT_TRUE(matches("Z", QUOTE("Z")));
  EXPECT_TRUE(matches("🥑", QUOTE("🥑")));

  // Octal (\nnn), hex (\xnn), extended octal (\unnnn or \Unnnnnnnn).
  EXPECT_TRUE(matches("\uD55C", QUOTE("한")));
  EXPECT_TRUE(matches("\U00010348", QUOTE("𐍈")));

  // FIXME: These strings are all rejected, but shouldn't be AFAICT. LLDB finds
  // that these are not valid utf8 sequences, but that's OK, the raw values
  // should still be printed out.
  EXPECT_FALSE(matches("\376", QUOTE("\\xfe"))); // \376 is 254 in decimal.
  EXPECT_FALSE(matches("\xfe", QUOTE("\\xfe"))); // \xfe is 254 in decimal.
}
