/**
 * Shared flow-source model for data read from a block device through the
 * `EFI_BLOCK_IO_PROTOCOL.ReadBlocks` method, declared in
 * `MdePkg/Include/Protocol/BlockIo.h`.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * The attacker-controlled contents read into the `Buffer` output parameter of:
 *
 * ```c
 * EFI_STATUS (EFIAPI *EFI_BLOCK_READ)(
 *   IN  EFI_BLOCK_IO_PROTOCOL *This,
 *   IN  UINT32                 MediaId,
 *   IN  EFI_LBA                Lba,
 *   IN  UINTN                  BufferSize,
 *   OUT VOID                  *Buffer);   // argument index 4
 * ```
 *
 * `ReadBlocks` is invoked indirectly through the protocol's function-pointer
 * field (`BlockIo->ReadBlocks (...)`), so the call site is an `ExprCall` whose
 * callee expression is a `FieldAccess` of the `ReadBlocks` field. The bytes it
 * writes come from a potentially malicious block device / partition table, so
 * the pointed-to buffer contents (`arg[*4]`) are treated as attacker-controlled.
 */
class Edk2BlockReadSource extends RemoteFlowSource {
  Edk2BlockReadSource() {
    exists(ExprCall call, Field f |
      call.getExpr().(FieldAccess).getTarget() = f and
      f.hasName("ReadBlocks") and
      f.getDeclaringType().getName().matches("%EFI_BLOCK_IO_PROTOCOL") and
      this.asIndirectExpr() = call.getArgument(4)
    )
  }

  override string getSourceType() { result = "data read from a block I/O device" }
}
