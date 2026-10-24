/**
 * Models EDK2 MemoryAllocationLib pool allocators
 * (`MdePkg/Include/Library/MemoryAllocationLib.h`) as CodeQL `AllocationFunction`s,
 * so queries can recover each call's allocation-size expression through the
 * standard `AllocationExpr` interface (`getSizeExpr()` / `getSizeBytes()`).
 */

import cpp
import semmle.code.cpp.models.interfaces.Allocation

/**
 * An EDK2 pool allocator whose first argument is the allocation size in bytes:
 *
 *  - `AllocatePool (UINTN AllocationSize)` and its `Runtime` / `Reserved` and
 *    zeroing (`...ZeroPool`) variants;
 *  - `AllocateCopyPool (UINTN AllocationSize, CONST VOID *Buffer)` and its
 *    `Runtime` / `Reserved` variants, which allocate `AllocationSize` bytes and
 *    then copy `Buffer` into them.
 *
 * All return the allocated buffer (`VOID *`) and take the size at argument 0,
 * so the model only needs `getSizeArg() = 0`. The page allocators
 * (`AllocatePages`, which sizes in `EFI_PAGE_SIZE` units) and `ReallocatePool`
 * (size at argument 1, old pointer at argument 2) have different shapes and are
 * intentionally not modeled here.
 */
class Edk2PoolAllocationFunction extends AllocationFunction {
  Edk2PoolAllocationFunction() {
    this.hasGlobalName([
        "AllocatePool", "AllocateZeroPool", "AllocateRuntimePool", "AllocateRuntimeZeroPool",
        "AllocateReservedPool", "AllocateReservedZeroPool", "AllocateCopyPool",
        "AllocateRuntimeCopyPool", "AllocateReservedCopyPool"
      ])
  }

  override int getSizeArg() { result = 0 }
}

/**
 * Holds if `f` is one of the private MemoryAllocationLib pool workers behind the
 * public `Allocate*Pool` API: `InternalAllocatePool`/`InternalAllocateZeroPool`
 * and their runtime/reserved/copy variants. Each initialises the buffer it has
 * just allocated with a `ZeroMem`/`CopyMem` sized to that same allocation (e.g.
 * `ZeroMem (Memory, AllocationSize)` in `InternalAllocateZeroPool`), so a
 * BaseMemoryLib length reached inside one of these routines is a library echo
 * over a correctly-sized buffer, not a real over-read.
 */
predicate isInternalAllocationFunction(Function f) {
  f.hasGlobalName([
      "InternalAllocatePool", "InternalAllocateZeroPool", "InternalAllocateRuntimePool",
      "InternalAllocateRuntimeZeroPool", "InternalAllocateReservedPool",
      "InternalAllocateReservedZeroPool", "InternalAllocateCopyPool",
      "InternalAllocateRuntimeCopyPool", "InternalAllocateReservedCopyPool"
    ])
}
