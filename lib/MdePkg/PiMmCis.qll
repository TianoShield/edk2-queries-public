/**
 * Models SMI (MMI) handler registration through the SMM and MM services
 * tables (`MdePkg/Include/Pi/PiSmmCis.h`, `MdePkg/Include/Pi/PiMmCis.h`).
 */

import cpp

/**
 * Holds if `call` is an indirect call through field `fieldName` of
 * `EFI_SMM_SYSTEM_TABLE2` (`gSmst`) or `EFI_MM_SYSTEM_TABLE` (`gMmst`).
 */
bindingset[fieldName]
private predicate isMmServicesCall(ExprCall call, string fieldName) {
  exists(Field f |
    call.getExpr().(FieldAccess).getTarget() = f and
    f.hasName(fieldName) and
    f.getDeclaringType().getName().matches(["%EFI_SMM_SYSTEM_TABLE2", "%EFI_MM_SYSTEM_TABLE"])
  )
}

/**
 * A call registering an SMI handler:
 *
 *     gSmst->SmiHandlerRegister (Handler, HandlerType, &DispatchHandle)
 *     gMmst->MmiHandlerRegister (Handler, HandlerType, &DispatchHandle)
 *
 * Once registered, the handler runs on every matching SMI until it is
 * unregistered with the returned `DispatchHandle`, including after
 * ExitBootServices, when the OS can raise the SMI.
 */
class Edk2SmiHandlerRegisterCall extends ExprCall {
  Edk2SmiHandlerRegisterCall() {
    isMmServicesCall(this, ["SmiHandlerRegister", "MmiHandlerRegister"])
  }

  /** Gets the registered handler function. */
  Function getHandler() { result = this.getArgument(0).getUnconverted().(FunctionAccess).getTarget() }

  /** Gets the `DispatchHandle` output argument. */
  Expr getDispatchHandleArgument() { result = this.getArgument(2) }
}

/**
 * A call unregistering an SMI handler:
 *
 *     gSmst->SmiHandlerUnRegister (DispatchHandle)
 *     gMmst->MmiHandlerUnRegister (DispatchHandle)
 */
class Edk2SmiHandlerUnRegisterCall extends ExprCall {
  Edk2SmiHandlerUnRegisterCall() {
    isMmServicesCall(this, ["SmiHandlerUnRegister", "MmiHandlerUnRegister"])
  }

  /** Gets the `DispatchHandle` argument. */
  Expr getDispatchHandle() { result = this.getArgument(0) }
}
