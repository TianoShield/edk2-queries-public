/**
 * Shared `TaintInheritingContent` model for the GPT primary header struct
 * `EFI_PARTITION_TABLE_HEADER`, defined in `MdePkg/Include/Uefi/UefiGpt.h`.
 *
 * `Tcg2MeasureGptTable` (and the TPM 1.2 sibling `TcgMeasureGptTable`) read the
 * primary header straight off disk into a buffer and then size allocations with
 * `PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry`
 * (CVE-2022-36763). The disk-read source model taints the buffer contents, but
 * reading a scalar field of a tainted struct does not inherit taint by default,
 * so this content model carries the disk taint into the size-controlling fields.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * The GPT primary header struct:
 *
 * ```c
 * typedef struct {
 *   EFI_TABLE_HEADER Header;
 *   EFI_LBA          MyLBA, AlternateLBA, FirstUsableLBA, LastUsableLBA;
 *   EFI_GUID         DiskGUID;
 *   EFI_LBA          PartitionEntryLBA;
 *   UINT32           NumberOfPartitionEntries;
 *   UINT32           SizeOfPartitionEntry;
 *   UINT32           PartitionEntryArrayCRC32;
 * } EFI_PARTITION_TABLE_HEADER;
 * ```
 */
class EfiPartitionTableHeaderStruct extends Struct {
  EfiPartitionTableHeaderStruct() {
    exists(TypedefType t |
      t.hasName("EFI_PARTITION_TABLE_HEADER") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * The scalar (integral) fields of the GPT header. The entire header is read
 * verbatim from disk, so every scalar field is attacker-controlled — the entry
 * count and entry size that form the `N * S` product, the partition-entry and
 * usable-range LBAs, and the array CRC. The `EFI_TABLE_HEADER` and `EFI_GUID`
 * sub-aggregates are excluded (not scalar, no arithmetic operand).
 */
private class EfiPartitionTableHeaderField extends Field {
  EfiPartitionTableHeaderField() {
    this.getDeclaringType().getUnderlyingType() instanceof EfiPartitionTableHeaderStruct and
    this.getType().getUnderlyingType() instanceof IntegralType
  }
}

/**
 * Taint on an `EFI_PARTITION_TABLE_HEADER` value (the disk-read buffer)
 * inherits into every scalar field, so a tainted header produces tainted
 * `NumberOfPartitionEntries`/`SizeOfPartitionEntry` (and the other scalar)
 * reads. The taint applies to the loaded field value, not to a pointee reached
 * through it.
 */
private class EfiPartitionTableHeaderTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  EfiPartitionTableHeaderTaintInheritingContent() {
    this.getField() instanceof EfiPartitionTableHeaderField
  }
}
