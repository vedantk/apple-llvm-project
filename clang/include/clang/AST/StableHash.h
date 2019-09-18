//===--- StableHash.h - An ABI-stable string hash ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The interface to an ABI-stable string hash algorithm.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_AST_STABLEHASH_H
#define CLANG_AST_STABLEHASH_H

#include <cstdint>

namespace llvm {
class StringRef;
}

namespace clang {
/// Compute a stable 64-bit hash of the given string.
///
/// The exact algorithm is the little-endian interpretation of the
/// non-doubled (i.e. 64-bit) result of applying a SipHash-2-4 using
/// a specific key value which can be found in the source.
///
/// By "stable" we mean that the result of this hash algorithm will
/// the same across different compiler versions and target platforms.
uint64_t getStableStringHash(llvm::StringRef string);

} // end namespace clang

#endif
