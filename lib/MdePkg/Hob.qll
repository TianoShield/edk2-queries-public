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

/**
 * Holds if `arg` supplies the bytes that `call` copies into a new GUID HOB:
 *
 *     VOID *BuildGuidDataHob (IN CONST EFI_GUID *Guid, IN VOID *Data, IN UINTN DataLength);
 *
 * or, in the two-step form, the `Data` of `CopyMem (Hob, Data, Size)` where
 * `Hob` is the buffer returned by `BuildGuidHob (&Guid, Size)`. HobLib's own
 * `BuildGuidDataHob` is that two-step form internally; it is excluded so a
 * value passed to it is reported once, at the caller.
 *
 * HOBs carry data from PEI into DXE (and into SMM), where consumers treat
 * their contents as trusted platform configuration.
 */
predicate isGuidHobDataArgument(FunctionCall call, Expr arg) {
  call.getTarget().hasGlobalName("BuildGuidDataHob") and arg = call.getArgument(1)
  or
  call.getTarget().hasGlobalName("CopyMem") and
  arg = call.getArgument(1) and
  not call.getEnclosingFunction().hasGlobalName("BuildGuidDataHob") and
  exists(FunctionCall build |
    build.getTarget().hasGlobalName("BuildGuidHob") and
    DataFlow::localExprFlow(build, call.getArgument(0).getUnconverted())
  )
}
