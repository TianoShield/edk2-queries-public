/**
 * Shared models for the EDK II HOB (Hand-Off Block) helpers defined in
 * `Hob.c` across EmbeddedPkg/Library/PrePiHobLib, UefiPayloadPkg/Library/
 * PayloadEntryHobLib, and similar HOB libraries.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * Holds if `f` is an EDK II `CreateHob` implementation, i.e. a function named
 * `CreateHob` whose two arguments are the requested HOB type and length:
 *
 *     VOID *
 *     CreateHob (
 *       IN  UINT16  HobType,
 *       IN  UINT16  HobLength
 *       )
 */
predicate isCreateHobFunction(Function f) {
  f.hasName("CreateHob") and
  f.getNumberOfParameters() = 2
}

/**
 * The `HobType` and `HobLength` parameters of `CreateHob`.
 *
 * Inside `CreateHob`'s body the requested length is aligned with
 * `HobLength = (UINT16)((HobLength + 0x7) & (~0x7));`, which overflows when
 * the caller-supplied length is close to `MAX_UINT16` (CVE-2022-36765).
 * Callers may compute `HobLength` from data parsed out of bootloader- or
 * host-supplied structures, so treating both parameters as tainted lets the
 * arithmetic-overflow analysis flag the unchecked alignment.
 */
class Edk2CreateHobParameterSource extends RemoteFlowSource {
  Edk2CreateHobParameterSource() {
    exists(Function f, Parameter p |
      isCreateHobFunction(f) and
      p = f.getParameter([0, 1]) and
      this.asParameter() = p
    )
  }

  override string getSourceType() { result = "parameter of CreateHob" }
}
