/**
 * Models the UEFI variable services, reached through the runtime services
 * table (`gRT`), the PEI read-only variable PPI and the SMM variable protocol
 * (which Traditional MM drivers also use).
 *
 * Variable contents live in the SPI flash variable store. Anything that can
 * write the store (pre-OS code, an OS-reachable `SetVariable` path, or a direct
 * flash write) controls the bytes a later `GetVariable` returns, so firmware
 * that consumes them must validate them first.
 */

import cpp
private import semmle.code.cpp.security.FlowSources as FS

/**
 * Holds if `s` is the struct named `name`, either directly (`struct _NAME`,
 * matched as `%NAME`) or through a typedef of an anonymous struct, as for
 * `EFI_RUNTIME_SERVICES`.
 */
bindingset[name]
private predicate isServiceStruct(Struct s, string name) {
  s.getName().matches("%" + name)
  or
  exists(TypedefType t | t.hasName(name) and t.getBaseType().getUnderlyingType() = s)
}

/**
 * Holds if `call` is an indirect call through the function-pointer field
 * `fieldName` of the service struct `structName`.
 */
bindingset[structName, fieldName]
private predicate isServiceCall(ExprCall call, string structName, string fieldName) {
  exists(Field f |
    call.getExpr().(FieldAccess).getTarget() = f and
    f.hasName(fieldName) and
    isServiceStruct(f.getDeclaringType(), structName)
  )
}

/**
 * Holds if `call` reads a UEFI variable and `dataIndex` is the index of its
 * `Data` output buffer:
 *
 *     EFI_RUNTIME_SERVICES.GetVariable (Name, Guid, Attributes, DataSize, Data)          // 4
 *     EFI_SMM_VARIABLE_PROTOCOL.SmmGetVariable (Name, Guid, Attributes, DataSize, Data)  // 4
 *     EFI_PEI_READ_ONLY_VARIABLE2_PPI.GetVariable (This, Name, Guid, Attributes,
 *                                                  DataSize, Data)                       // 5
 *
 * Library wrappers such as UefiLib's `GetVariable2` and MinPlatformPkg's
 * `VarLibGetVariable` end in one of these calls, so their results are covered
 * by ordinary interprocedural flow.
 */
predicate isGetVariableCall(ExprCall call, int dataIndex) {
  isServiceCall(call, "EFI_RUNTIME_SERVICES", "GetVariable") and dataIndex = 4
  or
  isServiceCall(call, "EFI_SMM_VARIABLE_PROTOCOL", "SmmGetVariable") and dataIndex = 4
  or
  isServiceCall(call, "EFI_PEI_READ_ONLY_VARIABLE2_PPI", "GetVariable") and dataIndex = 5
}

/**
 * The bytes a `GetVariable` call writes into its `Data` buffer: the output
 * argument after the call, at any indirection, so both a typed buffer
 * (`MemoryData`) and the address of a stack array (`&MemoryData`) are covered.
 *
 * Only the contents are a source. The `DataSize` written back cannot exceed
 * the caller's buffer size on success, so it is not treated as attacker data.
 */
class Edk2UefiVariableDataSource extends FS::LocalFlowSource {
  Edk2UefiVariableDataSource() {
    exists(ExprCall call, int dataIndex |
      isGetVariableCall(call, dataIndex) and
      this.asDefiningArgument() = call.getArgument(dataIndex)
    )
  }

  override string getSourceType() { result = "UEFI variable contents" }
}

/**
 * A call that writes a UEFI variable to the variable store:
 *
 *     EFI_RUNTIME_SERVICES.SetVariable (Name, Guid, Attributes, DataSize, Data)
 *     EFI_SMM_VARIABLE_PROTOCOL.SmmSetVariable (Name, Guid, Attributes, DataSize, Data)
 */
class Edk2SetVariableCall extends ExprCall {
  Edk2SetVariableCall() {
    isServiceCall(this, "EFI_RUNTIME_SERVICES", "SetVariable") or
    isServiceCall(this, "EFI_SMM_VARIABLE_PROTOCOL", "SmmSetVariable")
  }
}
