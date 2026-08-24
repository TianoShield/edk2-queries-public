/**
 * Shared flow-source model for data read from a disk device through the
 * `EFI_DISK_IO_PROTOCOL.ReadDisk` method, declared in
 * `MdePkg/Include/Protocol/DiskIo.h`.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * The attacker-controlled contents read into the `Buffer` output parameter of:
 *
 * ```c
 * EFI_STATUS (EFIAPI *EFI_DISK_READ)(
 *   IN  EFI_DISK_IO_PROTOCOL *This,
 *   IN  UINT32                MediaId,
 *   IN  UINT64                Offset,
 *   IN  UINTN                 BufferSize,
 *   OUT VOID                 *Buffer);   // argument index 4
 * ```
 *
 * `ReadDisk` is invoked indirectly through the protocol's function-pointer
 * field (`DiskIo->ReadDisk (...)`), so the call site is an `ExprCall` whose
 * callee expression is a `FieldAccess` of the `ReadDisk` field. The bytes it
 * writes come from a potentially malicious disk / partition table (e.g. the
 * GPT primary header parsed by `Tcg2MeasureGptTable`, CVE-2022-36763), so the
 * pointed-to buffer contents (`arg[*4]`) are treated as attacker-controlled.
 */
class Edk2DiskReadSource extends RemoteFlowSource {
  Edk2DiskReadSource() {
    exists(ExprCall call, Field f |
      call.getExpr().(FieldAccess).getTarget() = f and
      f.hasName("ReadDisk") and
      f.getDeclaringType().getName().matches("%EFI_DISK_IO_PROTOCOL") and
      this.asIndirectExpr() = call.getArgument(4)
    )
  }

  override string getSourceType() { result = "data read from a disk I/O device" }
}
