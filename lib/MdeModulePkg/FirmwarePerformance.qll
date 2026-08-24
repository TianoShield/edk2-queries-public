/**
 * Flow-source model for the OS-visible S3 performance table buffer that is
 * addressed by the pointer restored from
 * `RestoreLockBox(&gFirmwarePerformanceS3PointerGuid, ...)`.
 *
 * `MdeModulePkg/Universal/Acpi/FirmwarePerformanceDataTableDxe` allocates the
 * S3 performance table in `EfiReservedMemoryType` and publishes its physical
 * address through the FPDT ACPI table. The LockBox stores only the pointer
 * value, so the pointer itself is trusted, but the pointee lives in
 * OS-visible reserved memory and can be rewritten by the OS or a DMA-capable
 * peripheral between boot and S3 suspend. The buffer contents are therefore
 * attacker-controllable on the S3 resume path.
 *
 * Modelled as a `LocalFlowSource` because the data originates from the
 * firmware's own address space — just one whose contents the OS can
 * influence — rather than from a remote network endpoint.
 */

import cpp
private import semmle.code.cpp.security.FlowSources as FS
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

/** Holds if `e` is `&gFirmwarePerformanceS3PointerGuid`. */
private predicate isFpdtS3PointerGuidArg(Expr e) {
  exists(VariableAccess va |
    va = e.(AddressOfExpr).getOperand() and
    va.getTarget().hasName("gFirmwarePerformanceS3PointerGuid")
  )
}

/** The FPDT S3 performance table struct and its embedded record substructs. */
class S3PerformanceTableStruct extends Struct {
  S3PerformanceTableStruct() {
    exists(TypedefType t |
      t.hasName([
          "S3_PERFORMANCE_TABLE",
          "EFI_ACPI_5_0_FPDT_S3_RESUME_RECORD",
          "EFI_ACPI_5_0_FPDT_S3_SUSPEND_RECORD"
        ]) and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * Marks every field of the FPDT S3 performance-table struct family as
 * taint-inheriting: a read of any such field from a tainted parent struct
 * produces a tainted value, instead of requiring the field's own content to
 * be tainted. This lets the OS-influenced buffer's taint propagate into
 * field reads on `S3_PERFORMANCE_TABLE` and the embedded resume/suspend
 * records.
 */
private class S3PerformanceTableFieldContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  S3PerformanceTableFieldContent() {
    this.getField().getDeclaringType().getUnderlyingType() instanceof S3PerformanceTableStruct
  }
}

/**
 * The OS-influenced value written through argument 1 of a call to
 * `RestoreLockBox(&gFirmwarePerformanceS3PointerGuid, &Out, ...)`, at any
 * indirection level. The PEI consumer declares `Out` as
 * `EFI_PHYSICAL_ADDRESS` (a `UINT64`) and later casts it to
 * `S3_PERFORMANCE_TABLE *`, so the out-arg is `UINT64 *` rather than the
 * usual `T **`. Using `asDefiningArgument()` without a fixed indirection
 * index covers both the typed-pointer case (where the buffer is reached at
 * level 2) and this address-as-integer case (where the address itself, at
 * level 1, is the value reinterpreted as a pointer). The reached buffer
 * lives in `EfiReservedMemoryType` and is OS-visible, so its contents are
 * attacker-controllable.
 */
class Edk2FirmwarePerformanceS3FieldSource extends FS::LocalFlowSource {
  Edk2FirmwarePerformanceS3FieldSource() {
    exists(FunctionCall call |
      call.getTarget().hasGlobalName("RestoreLockBox") and
      isFpdtS3PointerGuidArg(call.getArgument(0)) and
      this.asDefiningArgument() = call.getArgument(1)
    )
  }

  override string getSourceType() {
    result = "buffer pointed to by FPDT S3 pointer restored from LockBox"
  }
}

/**
 * Holds if `nodeFrom` is a pointer that flows into the qualifier of a
 * `FieldAccess` on an FPDT S3 performance-table struct, and `nodeTo` is the
 * indirect value of the enclosing `&qualifier->fld` expression — i.e., the
 * struct content addressed by that field pointer.
 *
 * This bridges the address-of-field idiom
 *
 *   `Sub = &Parent->Field;`
 *
 * where CodeQL's default IR taint flow does not carry `Parent`'s value-level
 * taint through the address-of-field computation into `Sub`'s pointee content.
 * Adding this step lets taint propagate from a tainted `S3_PERFORMANCE_TABLE *`
 * to the content of `&...->S3Resume` / `&...->S3Suspend`, and on into the
 * embedded-record field reads that follow.
 */
predicate fpdtAddressOfFieldIndirectStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(AddressOfExpr aoe, FieldAccess fa |
    aoe.getOperand() = fa and
    fa.getTarget().getDeclaringType().getUnderlyingType() instanceof S3PerformanceTableStruct and
    nodeFrom.asExpr() = fa.getQualifier() and
    nodeTo.asIndirectExpr() = aoe
  )
}
