/**
 * Models selected EDK2 BaseMemoryLib functions.
 */

import semmle.code.cpp.models.interfaces.DataFlow

/**
 * `CopyMem(DestinationBuffer, SourceBuffer, Length)` copies bytes from the
 * source buffer to the destination buffer.
 */
class Edk2CopyMemFunction extends DataFlowFunction {
  Edk2CopyMemFunction() { this.hasGlobalName("CopyMem") }

  override predicate hasDataFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(1) and
    output.isParameterDeref(0)
  }
}

/**
 * Holds if BaseMemoryLib block function `f` accesses the buffer passed at
 * parameter index `bufParam` for the byte count passed at its length parameter
 * index `lengthParam`. This is the single source of truth for the argument
 * layout of the BaseMemoryLib block API:
 * - `CopyMem(Dest, Src, Length)` and `CompareMem(Buf1, Buf2, Length)`: buffers
 *   at index 0 and 1 (destination and source), length at index 2;
 * - `SetMem(Buf, Length, Value)`, `SetMem16/32/64/N`, `ZeroMem(Buf, Length)`,
 *   `ScanMem8/16/32/64(Buf, Length, Value)`, `IsZeroBuffer(Buf, Length)`: buffer
 *   at index 0, length at index 1.
 *
 * Both read and write buffers are included: `CopyMem`'s `Dest` and the
 * `SetMem*`/`ZeroMem` buffer are written, while `CopyMem`'s `Src`, both
 * `CompareMem` buffers, and the `ScanMem*`/`IsZeroBuffer` buffer are read.
 */
predicate baseMemoryLibBufferParameter(Function f, int bufParam, int lengthParam) {
  f.hasGlobalName(["CopyMem", "CompareMem"]) and bufParam = [0, 1] and lengthParam = 2
  or
  f.hasGlobalName([
      "SetMem", "SetMem16", "SetMem32", "SetMem64", "SetMemN", "ZeroMem", "ScanMem8", "ScanMem16",
      "ScanMem32", "ScanMem64", "IsZeroBuffer"
    ]) and
  bufParam = 0 and
  lengthParam = 1
}

/**
 * Holds if `p` is the `Length` parameter of a BaseMemoryLib block function
 * (index 2 for `CopyMem` / `CompareMem`, index 1 for the `SetMem*` / `ZeroMem` /
 * `ScanMem*` / `IsZeroBuffer` family), derived from `baseMemoryLibBufferParameter`.
 *
 * Attacker-controlled flow into such a length is the dedicated concern of
 * `TaintedBaseMemoryLibLength.ql`. Other queries (e.g. `ArithmeticTainted.ql`)
 * barrier this callee parameter so the length does not resurface as a false
 * positive in the wrapper's own bounds math — e.g. the `(Length - 1)` in
 * `CompareMem`'s `ASSERT ((Length - 1) <= MAX_ADDRESS - (UINTN)Buffer)`, which
 * the wrapper's leading `if (Length == 0) return ...` already makes safe.
 * Barriering the parameter (not the call-site argument) keeps the value live in
 * the caller, so caller-side arithmetic on the same value is still reported.
 */
predicate isBaseMemoryLibLengthParameter(Parameter p) {
  exists(Function f, int lengthParam |
    baseMemoryLibBufferParameter(f, _, lengthParam) and p = f.getParameter(lengthParam)
  )
}
