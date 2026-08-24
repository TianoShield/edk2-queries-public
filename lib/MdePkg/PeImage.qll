/**
 * Shared `TaintInheritingContent` models for PE/COFF header structs
 * defined in `MdePkg/Include/IndustryStandard/PeImage.h`.
 *
 * The CVE-2024-38796 sink in `PeCoffLoaderRelocateImage` reads
 * `RelocDir->VirtualAddress` and `RelocDir->Size` after first casting the
 * loaded image buffer to a typed header pointer:
 *
 * ```c
 * Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(ImageAddress + PeCoffHeaderOffset);
 * RelocDir = &Hdr.Pe32->OptionalHeader.DataDirectory[5];
 * ```
 *
 * The related Section walker in `PeCoffLoaderLoadImage` reads
 * `Section->VirtualAddress` and `Section->Misc.VirtualSize` after a
 * similar cast:
 *
 * ```c
 * FirstSection = (EFI_IMAGE_SECTION_HEADER *)(ImageAddress + sizeof (EFI_TE_IMAGE_HEADER));
 * Section      = FirstSection;
 * End          = PeCoffLoaderImageAddress (
 *                  ImageContext,
 *                  Section->VirtualAddress + Section->Misc.VirtualSize - 1,
 *                  ...);
 * ```
 *
 * Attacker-controlled bytes in the loaded image therefore need to inherit
 * into the scalar fields of these header structs (and into the
 * intermediate union member on the section header) for the taint chain to
 * reach the unguarded additions.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * The header data directory struct from `MdePkg/Include/IndustryStandard/PeImage.h`:
 *
 * ```c
 * typedef struct {
 *   UINT32 VirtualAddress;
 *   UINT32 Size;
 * } EFI_IMAGE_DATA_DIRECTORY;
 * ```
 */
class EfiImageDataDirectoryStruct extends Struct {
  EfiImageDataDirectoryStruct() {
    exists(TypedefType t |
      t.hasName("EFI_IMAGE_DATA_DIRECTORY") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class EfiImageDataDirectoryField extends Field {
  EfiImageDataDirectoryField() {
    this.getDeclaringType().getUnderlyingType() instanceof EfiImageDataDirectoryStruct and
    this.hasName(["VirtualAddress", "Size"])
  }
}

/**
 * Taint on an `EFI_IMAGE_DATA_DIRECTORY` value flows into the scalar
 * `VirtualAddress` and `Size` fields. Together with the
 * `PE_COFF_LOADER_IMAGE_CONTEXT.ImageAddress` content model in
 * `lib/MdePkg/PeCoffLib.qll`, this is what allows taint on the loaded PE/COFF
 * bytes to reach the `RelocDir->VirtualAddress + RelocDir->Size - 1`
 * sink of CVE-2024-38796.
 */
private class EfiImageDataDirectoryTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  EfiImageDataDirectoryTaintInheritingContent() {
    this.getField() instanceof EfiImageDataDirectoryField
  }
}

/**
 * The `OptionalHeader` and `DataDirectory` fields on PE/COFF header
 * structs. These are the intermediate steps from the outer header down
 * to `EFI_IMAGE_DATA_DIRECTORY[5]`:
 *
 * ```c
 * Hdr.Pe32  -> OptionalHeader -> DataDirectory[5] -> {VirtualAddress, Size}
 * Hdr.Pe32p -> OptionalHeader -> DataDirectory[5] -> {VirtualAddress, Size}
 * Hdr.Te    -> DataDirectory  ->                     {VirtualAddress, Size}
 * ```
 *
 * The declaring struct must be one of `EFI_IMAGE_NT_HEADERS32`,
 * `EFI_IMAGE_NT_HEADERS64`, `EFI_TE_IMAGE_HEADER`,
 * `EFI_IMAGE_OPTIONAL_HEADER32`, or `EFI_IMAGE_OPTIONAL_HEADER64`.
 */
private class EfiImageHeaderWrapperField extends Field {
  EfiImageHeaderWrapperField() {
    exists(TypedefType t |
      t.hasName([
          "EFI_IMAGE_NT_HEADERS32", "EFI_IMAGE_NT_HEADERS64", "EFI_TE_IMAGE_HEADER",
          "EFI_IMAGE_OPTIONAL_HEADER32", "EFI_IMAGE_OPTIONAL_HEADER64"
        ]) and
      t.getBaseType().getUnderlyingType() = this.getDeclaringType().getUnderlyingType()
    ) and
    this.hasName(["OptionalHeader", "DataDirectory"])
  }
}

/**
 * Taint on any of the PE/COFF header wrapper structs flows through the
 * `OptionalHeader` and `DataDirectory` fields that the EDK II loader
 * walks before reaching the `RelocDir` sub-struct.
 */
private class EfiImageHeaderWrapperTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  EfiImageHeaderWrapperTaintInheritingContent() {
    this.getField() instanceof EfiImageHeaderWrapperField
  }
}

/**
 * The image section table entry from
 * `MdePkg/Include/IndustryStandard/PeImage.h`:
 *
 * ```c
 * typedef struct {
 *   UINT8     Name[EFI_IMAGE_SIZEOF_SHORT_NAME];
 *   union {
 *     UINT32    PhysicalAddress;
 *     UINT32    VirtualSize;
 *   } Misc;
 *   UINT32    VirtualAddress;
 *   UINT32    SizeOfRawData;
 *   UINT32    PointerToRawData;
 *   ...
 * } EFI_IMAGE_SECTION_HEADER;
 * ```
 */
class EfiImageSectionHeaderStruct extends Struct {
  EfiImageSectionHeaderStruct() {
    exists(TypedefType t |
      t.hasName("EFI_IMAGE_SECTION_HEADER") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class EfiImageSectionHeaderField extends Field {
  EfiImageSectionHeaderField() {
    this.getDeclaringType().getUnderlyingType() instanceof EfiImageSectionHeaderStruct
  }
}

/**
 * The anonymous union of `EFI_IMAGE_SECTION_HEADER.Misc`. CodeQL exposes
 * the union as a distinct struct-like type with `PhysicalAddress` and
 * `VirtualSize` members; we identify it by looking up the field named
 * `Misc` on the section header.
 */
private class EfiImageSectionHeaderMiscUnion extends Struct {
  EfiImageSectionHeaderMiscUnion() {
    exists(Field miscField |
      miscField.hasName("Misc") and
      miscField.getDeclaringType().getUnderlyingType() instanceof EfiImageSectionHeaderStruct and
      miscField.getType().getUnderlyingType() = this
    )
  }
}

private class EfiImageSectionHeaderMiscField extends Field {
  EfiImageSectionHeaderMiscField() {
    this.getDeclaringType().getUnderlyingType() instanceof EfiImageSectionHeaderMiscUnion
  }
}

/**
 * Taint on an `EFI_IMAGE_SECTION_HEADER` value flows into every field of
 * the section table entry, including the union members of `Misc`. This
 * carries attacker-controlled image bytes through:
 *
 *  - `Section->VirtualAddress` — the section RVA;
 *  - `Section->Misc.VirtualSize` — the section virtual size (the inner
 *    union field that participates in the `PeCoffLoaderLoadImage`
 *    addition `Section->VirtualAddress + Section->Misc.VirtualSize - 1`);
 *  - `Section->SizeOfRawData`, `Section->PointerToRawData`, etc., that
 *    appear in adjacent header-walking arithmetic.
 */
private class EfiImageSectionHeaderTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  EfiImageSectionHeaderTaintInheritingContent() {
    this.getField() instanceof EfiImageSectionHeaderField or
    this.getField() instanceof EfiImageSectionHeaderMiscField
  }
}

/**
 * Bridges the gap CodeQL's IR-based dataflow leaves across the `Misc`
 * anonymous union of `EFI_IMAGE_SECTION_HEADER`. The two consecutive
 * `TaintInheritingContent` reads — `*Section` → `Section->Misc` →
 * `Section->Misc.{VirtualSize, PhysicalAddress}` — do not always compose
 * through the intermediate union value, so taint on the section pointee
 * fails to reach the scalar leaf. Seed the leaf union-member access
 * directly from the section pointee that the loader dereferences.
 */
predicate efiImageSectionHeaderMiscUnionStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(FieldAccess miscFa, FieldAccess leafFa |
    miscFa.getType().getUnderlyingType() instanceof EfiImageSectionHeaderMiscUnion and
    leafFa.getQualifier() = miscFa and
    node1.asIndirectExpr() = miscFa.getQualifier() and
    node2.asExpr() = leafFa
  )
}
