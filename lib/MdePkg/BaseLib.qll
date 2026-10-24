/**
 * Models for EDK2 BaseLib fixed-width integer multiplication helpers
 * (`MdePkg/Library/BaseLib`).
 *
 * BaseLib exposes public multiply wrappers — `MultU64x32` (`MultU64x32.c`),
 * `MultU64x64` (`MultU64x64.c`) and `MultS64x64` (`MultS64x64.c`) — each of
 * which forwards to an `InternalMath*` routine (`Math64.c`) that performs the
 * raw `Multiplicand * Multiplier`:
 *
 *     UINT64 MultU64x32 (UINT64 Multiplicand, UINT32 Multiplier) {
 *       return InternalMathMultU64x32 (Multiplicand, Multiplier);
 *     }
 *     UINT64 InternalMathMultU64x32 (UINT64 Multiplicand, UINT32 Multiplier) {
 *       return Multiplicand * Multiplier;   // the multiply that can overflow
 *     }
 *
 * The product can overflow the result width, but the multiplication AST node
 * lives inside library code. These models let an overflow query surface the
 * alert at the *caller* instead of inside BaseLib:
 *  - [[Edk2MultiplyCall]] exposes the factor arguments at a wrapper call site
 *    as the operands to flag;
 *  - [[Edk2InternalMultiplyFunction]] marks the BaseLib internal routines
 *    whose multiplication should therefore be ignored as a sink location.
 */

import cpp

/**
 * A BaseLib public fixed-width integer multiply wrapper: `MultU64x32`,
 * `MultU64x64` or `MultS64x64`. Each takes the multiplicand as parameter 0 and
 * the multiplier as parameter 1 and returns their product.
 */
class Edk2MultiplyFunction extends Function {
  Edk2MultiplyFunction() { this.hasGlobalName(["MultU64x32", "MultU64x64", "MultS64x64"]) }
}

/**
 * A BaseLib internal multiplication routine — `InternalMathMultU64x32` or
 * `InternalMathMultU64x64` (`Math64.c`) — whose body is the raw
 * `Multiplicand * Multiplier`. The multiply here is library plumbing reached
 * through a public wrapper; overflow should be attributed to that wrapper's
 * call site, so queries treat arithmetic in these functions as a non-sink
 * location.
 */
class Edk2InternalMultiplyFunction extends Function {
  Edk2InternalMultiplyFunction() {
    this.hasGlobalName(["InternalMathMultU64x32", "InternalMathMultU64x64"])
  }
}

/**
 * A call to a BaseLib fixed-width multiply wrapper (see
 * [[Edk2MultiplyFunction]]). Its factor arguments are the multiplication
 * operands; a query that flags unguarded integer multiplication can use them
 * as sinks so the alert points at the caller rather than into the BaseLib
 * `InternalMath*` implementation.
 */
class Edk2MultiplyCall extends FunctionCall {
  Edk2MultiplyCall() { this.getTarget() instanceof Edk2MultiplyFunction }

  /** Gets one of the two factor arguments (multiplicand or multiplier). */
  Expr getAFactorArgument() { result = this.getArgument([0, 1]) }
}
