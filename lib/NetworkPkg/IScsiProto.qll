/**
 * Shared TaintInheritingContent models for types defined in
 * NetworkPkg/IScsiDxe/IScsiProto.h.
 */

import cpp
private import semmle.code.cpp.security.FlowSources as FS
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

class IscsiReadyToTransferStruct extends Struct {
  IscsiReadyToTransferStruct() {
    exists(TypedefType t |
      t.hasName("ISCSI_READY_TO_TRANSFER") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class IscsiReadyToTransferField extends Field {
  IscsiReadyToTransferField() {
    this.getDeclaringType().getUnderlyingType() instanceof IscsiReadyToTransferStruct and
    this.hasName(["BufferOffset", "DesiredDataTransferLength"])
  }
}

/**
 * Models the attacker-controlled scalar length fields of:
 *
 * `typedef struct _ISCSI_READY_TO_TRANSFER {`
 * `  ...`
 * `  UINT32 BufferOffset;`
 * `  UINT32 DesiredDataTransferLength;`
 * `} ISCSI_READY_TO_TRANSFER;`
 *
 * Taint on an R2T PDU header object inherits to the field values
 * `BufferOffset` and `DesiredDataTransferLength`. Those fields are later copied
 * into `Tcb->XferContext.Offset` and `Tcb->XferContext.DesiredLength`.
 */
private class IscsiReadyToTransferTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  IscsiReadyToTransferTaintInheritingContent() {
    this.getField() instanceof IscsiReadyToTransferField
  }
}

/**
 * The `DataSegmentLength[3]` field shared by every iSCSI PDU header struct
 * (`ISCSI_BASIC_HEADER`, `ISCSI_LOGIN_RESPONSE`, `ISCSI_READY_TO_TRANSFER`,
 * ...). It is a big-endian 24-bit byte count that `ISCSI_GET_DATASEG_LEN`
 * reassembles with the `NTOH24` macro. Matched generically by field name and
 * `UINT8[3]` shape so every PDU header variant is covered without hardcoding
 * each struct name.
 */
private class IscsiDataSegmentLengthField extends Field {
  IscsiDataSegmentLengthField() {
    this.hasName("DataSegmentLength") and
    exists(ArrayType at |
      at = this.getUnspecifiedType() and
      at.getBaseType().getSize() = 1 and
      at.getArraySize() = 3
    )
  }
}

/**
 * Models the attacker-controlled 24-bit data-segment length field:
 *
 * `typedef struct _ISCSI_BASIC_HEADER {`
 * `  ...`
 * `  UINT8 DataSegmentLength[3];`
 * `  ...`
 * `} ISCSI_BASIC_HEADER;`
 *
 * Taint on a received PDU header object inherits into the `DataSegmentLength`
 * byte array, so the `(src)[0]/(src)[1]/(src)[2]` element reads of
 * `NTOH24 (((ISCSI_BASIC_HEADER *) PduHdr)->DataSegmentLength)` are tainted and
 * the reassembled `DataSegLen` stays tainted. In `IScsiProcessLoginRsp` that
 * length flows through `IScsiUpdateTargetAddress` into
 * `IScsiBuildKeyValueList`, whose unguarded `Len--` underflows below zero
 * (CVE-2024-38805). The taint applies to the array field's element values, not
 * to a pointee reached through it.
 */
private class IscsiDataSegmentLengthTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  IscsiDataSegmentLengthTaintInheritingContent() {
    this.getField() instanceof IscsiDataSegmentLengthField
  }
}

/**
 * Holds if `e` is a component of a byte-order assembly: a positioned byte
 * (a left-shift by a constant amount, e.g. `(src)[0] << 16`) or a nested
 * byte-order-assembly OR ([[isByteOrderAssemblyOr]]).
 */
predicate isByteOrderAssemblyComponent(Expr e) {
  e.(LShiftExpr).getRightOperand().isConstant()
  or
  isByteOrderAssemblyOr(e)
}

/**
 * Holds if `orExpr` reassembles a multi-byte scalar from its positioned bytes
 * with bitwise OR — the shape of a hand-rolled network byte-order macro. The
 * motivating instance is iSCSI's `NTOH24`, defined in
 * `NetworkPkg/IScsiDxe/IScsiProto.h`:
 *
 * `#define NTOH24(src)  (((src)[0] << 16) | ((src)[1] << 8) | ((src)[2]))`
 *
 * (The `NTOHL`/`NTOHS`/`NTOHLL`/`NTOHLLL` family in `NetLib.h` instead calls the
 * `SwapBytes*` intrinsics, modeled in `lib/MdePkg/BaseLibSwapBytes.qll`, so it
 * does not have this inline-assembly shape.) At least one operand must be a
 * shifted byte or a nested assembly, distinguishing a byte reassembly from an
 * unrelated OR of two independent values.
 *
 * `ArithmeticTainted.ql` uses this as an exception to its
 * both-operands-non-constant barrier: the OR reconstructs one attacker value
 * from its own bytes (a first-order taint carrier), so it must not be treated
 * as the second-order composite the barrier blocks. Without the exception taint
 * dies inside `ISCSI_GET_DATASEG_LEN`, hiding the CVE-2024-38805
 * `IScsiBuildKeyValueList` `Len--` underflow.
 */
predicate isByteOrderAssemblyOr(BitwiseOrExpr orExpr) {
  isByteOrderAssemblyComponent(orExpr.getLeftOperand()) or
  isByteOrderAssemblyComponent(orExpr.getRightOperand())
}

/**
 * The attacker-controlled packet contents returned by:
 *
 * `EFI_STATUS IScsiReceivePdu(ISCSI_CONNECTION *Conn, NET_BUF **Pdu, ...)`
 *
 * `IScsiReceivePdu` reads the PDU header and optional data segment with
 * `TcpIoReceive`, assembles them into a `NET_BUF`, and stores that packet
 * through `Pdu` (argument 1).
 */
class Edk2IScsiReceivePduSource extends FS::RemoteFlowSource {
  Edk2IScsiReceivePduSource() {
    exists(FunctionCall call |
      call.getTarget().hasGlobalName("IScsiReceivePdu") and
      this.asDefiningArgument() = call.getArgument(1)
    )
  }

  override string getSourceType() { result = "data received by IScsiReceivePdu" }
}
