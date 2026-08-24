/**
 * Models for the EDK2 BaseLib byte-order swap helpers
 * (`MdePkg/Library/BaseLib/SwapBytes{16,32,64}.c`), reached through the
 * NetworkPkg `NTOHS` / `NTOHL` / `NTOHLL` macros (`NetLib.h`).
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint

/**
 * A BaseLib fixed-width byte-order swap: `SwapBytes16`, `SwapBytes32`, or
 * `SwapBytes64`. Each takes the value as parameter 0 and returns the
 * byte-reversed value.
 *
 * Modeled flow: `arg[0] -> return`. The swap is value-preserving for taint —
 * a byte-reversed attacker-controlled value is still fully attacker-controlled
 * — so a length read from a packet stays tainted across `NTOHS`/`NTOHL`. An
 * explicit model is required (not just the body) because the swap is
 * implemented as `(hi << k) | (lo >> k)`, whose `|` of two non-constant halves
 * is removed by the "both operands non-constant" arithmetic barrier; the model
 * edge bypasses that internal node.
 */
class Edk2SwapBytesTaintFunction extends Function, TaintFunction {
  Edk2SwapBytesTaintFunction() {
    this.hasGlobalName(["SwapBytes16", "SwapBytes32", "SwapBytes64"])
  }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameter(0) and
    output.isReturnValue()
  }
}
