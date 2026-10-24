/**
 * Scope filter for all vendored third-party crypto sources in CryptoPkg.
 *
 * EDK2 vendors two upstream crypto libraries verbatim under CryptoPkg:
 * OpenSSL (`OpensslLib/openssl/`) and MbedTLS (`MbedTlsLib/mbedtls/`). Both
 * manage their own buffers and lengths internally and are out of scope for
 * these EDK2-focused queries, so flow through them (and alerts inside them)
 * are suppressed. EDK2's own wrappers (`BaseCryptLib`, the `MbedTlsLib` /
 * `OpensslLib` shim `.c` files) are *not* matched and remain in scope.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import lib.CryptoPkg.OpensslLib
import lib.CryptoPkg.MbedTlsLib

/** Holds if `f` is a vendored third-party crypto file (OpenSSL or MbedTLS). */
predicate isThirdPartyCryptoFile(File f) { isOpensslFile(f) or isMbedTlsFile(f) }

/** Holds if `node` is in a vendored third-party crypto file (OpenSSL or MbedTLS). */
predicate isThirdPartyCryptoNode(DataFlow::Node node) {
  isOpensslNode(node) or isMbedTlsNode(node)
}
