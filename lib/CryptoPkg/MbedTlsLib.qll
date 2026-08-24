/** Scope filter for vendored third-party MbedTLS sources in CryptoPkg. */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Holds if `f` is a vendored MbedTLS source file (a `mbedtls/` path
 * component), i.e. the upstream tree under `CryptoPkg/Library/MbedTlsLib/mbedtls/`,
 * not EDK2's own `MbedTlsLib` wrappers.
 */
predicate isMbedTlsFile(File f) { f.getRelativePath().matches("%/mbedtls/%") }

/** Holds if `node` is in a vendored MbedTLS file (a `mbedtls/` path component). */
predicate isMbedTlsNode(DataFlow::Node node) { isMbedTlsFile(node.getLocation().getFile()) }
