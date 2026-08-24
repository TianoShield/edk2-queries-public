/**
 * Models of the EDK2 TPM measure-boot GPT header sanitizers.
 *
 * `SecurityPkg/Library/DxeTpmMeasureBootLib/DxeTpmMeasureBootLibSanitization.c`
 * and the parallel `DxeTpm2MeasureBootLib/DxeTpm2MeasureBootLibSanitization.c`
 * define `TpmSanitizeEfiPartitionTableHeader` /
 * `Tpm2SanitizeEfiPartitionTableHeader`, which validate a GPT
 * `EFI_PARTITION_TABLE_HEADER` read from disk before it is used. Among other
 * checks they bound the fields that later feed BaseLib multiplications against
 * `MAX_UINT64`:
 *
 *     // "This will be used later for multiplication"
 *     if (PrimaryHeader->PartitionEntryLBA > DivU64x32 (MAX_UINT64, BlockIo->Media->BlockSize))
 *       return EFI_DEVICE_ERROR;
 *     ...
 *     if (PrimaryHeader->NumberOfPartitionEntries > DivU64x32 (MAX_UINT64, PrimaryHeader->SizeOfPartitionEntry))
 *       return EFI_DEVICE_ERROR;
 *
 * A successful call therefore establishes a `MAX_UINT64` headroom bound on
 * those fields. That makes a *64-bit* product of them (e.g.
 * `MultU64x32 (PartitionEntryLBA, BlockSize)`) non-overflowing — but it does
 * NOT make a 32-bit product safe, so this model is only sound for suppressing
 * overflow of fixed-width 64-bit multiply wrappers, not the UINT32
 * `NumberOfPartitionEntries * SizeOfPartitionEntry` of CVE-2022-36763.
 */

import cpp

/**
 * An EDK2 GPT partition-table-header sanitizer
 * (`TpmSanitizeEfiPartitionTableHeader` / `Tpm2SanitizeEfiPartitionTableHeader`).
 * Parameter 0 is the `EFI_PARTITION_TABLE_HEADER *` it validates; a successful
 * (`!EFI_ERROR`) return bounds that header's multiply-relevant fields.
 */
class Edk2PartitionTableHeaderSanitizer extends Function {
  Edk2PartitionTableHeaderSanitizer() { this.getName().matches("%SanitizeEfiPartitionTableHeader") }
}

/** A call to an [[Edk2PartitionTableHeaderSanitizer]]. */
class Edk2PartitionTableHeaderSanitizerCall extends FunctionCall {
  Edk2PartitionTableHeaderSanitizerCall() {
    this.getTarget() instanceof Edk2PartitionTableHeaderSanitizer
  }

  /** Gets the `EFI_PARTITION_TABLE_HEADER *` pointer being validated. */
  Expr getHeaderPointer() { result = this.getArgument(0) }
}
