/** Scope filter for vendored third-party OpenSSL sources in CryptoPkg. */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Holds if `f` is a vendored OpenSSL source file (an `openssl/` path
 * component), i.e. the upstream tree under `CryptoPkg/Library/OpensslLib/openssl/`,
 * not EDK2's own `BaseCryptLib` wrappers.
 */
predicate isOpensslFile(File f) { f.getRelativePath().matches("%/openssl/%") }

/** Holds if `node` is in a vendored OpenSSL file (an `openssl/` path component). */
predicate isOpensslNode(DataFlow::Node node) { isOpensslFile(node.getLocation().getFile()) }
