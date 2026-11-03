/**
 * Models random number generator interfaces: RngLib
 * (`MdePkg/Include/Library/RngLib.h`) and `EFI_RNG_PROTOCOL`
 * (`MdePkg/Include/Protocol/Rng.h`). CryptoPkg's `RandomBytes` extends
 * `Edk2RandomNumberCall` in `lib/CryptoPkg/BaseCryptLib.qll`.
 */

import cpp

/**
 * A call that fills a buffer with random data and reports failure only
 * through its return value. When it fails, the buffer holds whatever it held
 * before (often uninitialized stack), so the result must be checked before
 * the buffer is used as a key, salt or nonce.
 */
abstract class Edk2RandomNumberCall extends Call {
  /** Gets the argument pointing to the buffer that receives the random data. */
  abstract Expr getOutputArgument();
}

/**
 * `BOOLEAN GetRandomNumber16/32/64/128 (OUT UINTxx *Rand)` from RngLib, which
 * returns FALSE when the hardware or protocol RNG does not deliver.
 */
private class RngLibRandomNumberCall extends Edk2RandomNumberCall, FunctionCall {
  RngLibRandomNumberCall() {
    this.getTarget()
        .hasGlobalName(["GetRandomNumber16", "GetRandomNumber32", "GetRandomNumber64",
              "GetRandomNumber128"])
  }

  override Expr getOutputArgument() { result = this.getArgument(0) }
}

/**
 * `EFI_STATUS EFI_RNG_PROTOCOL.GetRNG (This, RNGAlgorithm, RNGValueLength,
 * RNGValue)`, which returns an error status when no entropy is available.
 */
private class RngProtocolGetRngCall extends Edk2RandomNumberCall, ExprCall {
  RngProtocolGetRngCall() {
    exists(Field f |
      this.getExpr().(FieldAccess).getTarget() = f and
      f.hasName("GetRNG") and
      f.getDeclaringType().getName().matches("%EFI_RNG_PROTOCOL")
    )
  }

  override Expr getOutputArgument() { result = this.getArgument(3) }
}
