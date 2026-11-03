/**
 * @name SMI handler that writes UEFI variables is never unregistered
 * @description An SMI handler that can write UEFI variables is registered and
 *              never unregistered, so it stays callable after
 *              ExitBootServices and the OS can drive it to change persistent
 *              firmware state (for example to set a BIOS password). Handlers
 *              meant for pre-boot callers should be unregistered at
 *              ExitBootServices and LegacyBoot.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/edk2-smi-handler-writes-variable-never-unregistered
 * @tags security
 *       external/cwe/cwe-749
 *       external/cwe/cwe-284
 */

import cpp
import lib.Edk2

/** Gets the variable or field that receives the dispatch handle of `reg` (`&Handle`, `&Private->Handle`). */
Variable dispatchHandleTarget(Edk2SmiHandlerRegisterCall reg) {
  result =
    reg.getDispatchHandleArgument()
        .getUnconverted()
        .(AddressOfExpr)
        .getOperand()
        .(VariableAccess)
        .getTarget()
}

/**
 * Holds if the handler registered by `reg` is unregistered somewhere: its
 * dispatch handle variable or field is passed to an unregister call, or the
 * handler unregisters itself through its own `DispatchHandle` parameter.
 */
predicate isUnregistered(Edk2SmiHandlerRegisterCall reg) {
  exists(Edk2SmiHandlerUnRegisterCall unreg, VariableAccess va |
    va = unreg.getDispatchHandle().getUnconverted()
  |
    va.getTarget() = dispatchHandleTarget(reg)
    or
    va.getTarget() = reg.getHandler().getParameter(0)
  )
}

/** Holds if `handler` reaches the variable write `write` through direct calls. */
predicate canWriteVariable(Function handler, Edk2SetVariableCall write) {
  handler.calls*(write.getEnclosingFunction())
}

from Edk2SmiHandlerRegisterCall reg, Function handler, Edk2SetVariableCall write
where
  handler = reg.getHandler() and
  not isUnregistered(reg) and
  write =
    min(Edk2SetVariableCall w, Location l |
      canWriteVariable(handler, w) and l = w.getLocation()
    |
      w order by l.getFile().getAbsolutePath(), l.getStartLine(), l.getStartColumn()
    )
select reg,
  "SMI handler $@ can write UEFI variables (for example $@) and is never unregistered, so the OS can still invoke it after ExitBootServices.",
  handler, handler.getName(), write, "this write"
