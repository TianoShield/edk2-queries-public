/**
 * Models selected BaseCryptLib functions (`CryptoPkg/Include/Library/BaseCryptLib.h`).
 */

import cpp
import lib.MdePkg.RngLib

/**
 * `BOOLEAN RandomBytes (Output, Size)`, which returns FALSE when
 * `RAND_bytes () != 1`, leaving `Output` unwritten.
 *
 * `RandomSeed` is not modeled: it has no output buffer, and when seeding
 * fails the later `RandomBytes` call fails and reports it.
 */
private class BaseCryptLibRandomCall extends Edk2RandomNumberCall, FunctionCall {
  BaseCryptLibRandomCall() { this.getTarget().hasGlobalName("RandomBytes") }

  override Expr getOutputArgument() { result = this.getArgument(0) }
}

/**
 * Holds if parameter `index` of `f` receives secret material that must not
 * outlive its use:
 *
 *     Pkcs5HashPassword (PasswordLength, Password, SaltLength, Salt, ...)  // 1
 */
predicate isSecretParameter(Function f, int index) {
  f.hasGlobalName("Pkcs5HashPassword") and index = 1
}
