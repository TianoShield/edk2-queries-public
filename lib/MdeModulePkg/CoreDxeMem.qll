/**
 * Shared models and arithmetic-taint barriers for DXE core memory APIs:
 * `CoreAllocatePages`, `CoreFreePages`, and `CoreFreePool`, defined in
 * `MdeModulePkg/Core/Dxe/Mem/Page.c` and `MdeModulePkg/Core/Dxe/Mem/Pool.c`.
 *
 * Stopping flow at these call sites suppresses false positives where caller
 * taint propagates into allocator/free bookkeeping arithmetic
 * (`CoreUpdateProfile`, `ApplyMemoryProtectionPolicy`, `GuardFreedPages...`,
 * `HeapGuard.c`, `MemoryProfileRecord.c`, `MemoryProtection.c`) — the
 * bookkeeping operates on DXE-core-managed bookkeeping ranges, not on
 * attacker-influenced values that the caller is responsible for validating.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Models:
 *
 * ```c
 * EFI_STATUS CoreAllocatePages (
 *   IN  EFI_ALLOCATE_TYPE     Type,
 *   IN  EFI_MEMORY_TYPE       MemoryType,
 *   IN  UINTN                 NumberOfPages,
 *   OUT EFI_PHYSICAL_ADDRESS  *Memory);
 * ```
 */
class DxeCoreAllocatePagesFunction extends Function {
  DxeCoreAllocatePagesFunction() { this.hasGlobalName("CoreAllocatePages") }
}

/**
 * Models:
 *
 * ```c
 * EFI_STATUS CoreFreePages (
 *   IN EFI_PHYSICAL_ADDRESS Memory,
 *   IN UINTN                NumberOfPages);
 * ```
 */
class DxeCoreFreePagesFunction extends Function {
  DxeCoreFreePagesFunction() { this.hasGlobalName("CoreFreePages") }
}

/** Models `EFI_STATUS CoreFreePool(IN VOID *Buffer)`. */
class DxeCoreFreePoolFunction extends Function {
  DxeCoreFreePoolFunction() { this.hasGlobalName("CoreFreePool") }
}

/** Holds if `node` is the value or pointee-content node for `call` argument `i`. */
private predicate isArgumentNode(DataFlow::Node node, FunctionCall call, int i) {
  node.asExpr() = call.getArgument(i) or node.asIndirectExpr() = call.getArgument(i)
}

/** Holds if `node` is an argument passed to `CoreAllocatePages`. */
predicate isDxeCoreAllocateArgument(DataFlow::Node node) {
  exists(FunctionCall call, int i |
    call.getTarget() instanceof DxeCoreAllocatePagesFunction and
    i in [0 .. 3] and
    isArgumentNode(node, call, i)
  )
}

/** Holds if `node` is an argument passed to `CoreFreePool` or `CoreFreePages`. */
predicate isDxeCoreFreeArgument(DataFlow::Node node) {
  exists(FunctionCall call |
    call.getTarget() instanceof DxeCoreFreePoolFunction and
    isArgumentNode(node, call, 0)
  )
  or
  exists(FunctionCall call, int i |
    call.getTarget() instanceof DxeCoreFreePagesFunction and
    i in [0 .. 1] and
    isArgumentNode(node, call, i)
  )
}
