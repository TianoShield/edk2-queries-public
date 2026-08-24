/**
 * Shared models for `PE_COFF_LOADER_IMAGE_CONTEXT` and the
 * `PE_COFF_LOADER_READ_FILE` callback, both declared in
 * `MdePkg/Include/Library/PeCoffLib.h`.
 *
 * Provides:
 *  - a flow source for bytes read from a PE/COFF image via the
 *    `PE_COFF_LOADER_READ_FILE` callback installed on
 *    `PE_COFF_LOADER_IMAGE_CONTEXT.ImageRead`;
 *  - a function-local bridge from `*ImageContext` (struct content) to
 *    indirect reads through reinterpret-cast pointers
 *    (`EFI_IMAGE_NT_HEADERS32 *`, `EFI_IMAGE_NT_HEADERS64 *`,
 *    `EFI_TE_IMAGE_HEADER *`, `EFI_IMAGE_SECTION_HEADER *`); the bridge
 *    restores the alias that CodeQL's IR-based dataflow drops at the
 *    `(UINTN)` cast in idioms like
 *    `(EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageContext->ImageAddress + N)`.
 */

import cpp
private import semmle.code.cpp.security.FlowSources as FS
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * The PE/COFF loader image context defined in
 * `MdePkg/Include/Library/PeCoffLib.h`:
 *
 * ```c
 * typedef struct {
 *   PHYSICAL_ADDRESS         ImageAddress;     // loaded image buffer
 *   ...
 *   PE_COFF_LOADER_READ_FILE ImageRead;        // callback
 *   VOID                    *Handle;           // passed to ImageRead
 *   ...
 *   UINT32                   PeCoffHeaderOffset;
 *   ...
 * } PE_COFF_LOADER_IMAGE_CONTEXT;
 * ```
 */
class PeCoffLoaderImageContextStruct extends Struct {
  PeCoffLoaderImageContextStruct() {
    exists(TypedefType t |
      t.hasName("PE_COFF_LOADER_IMAGE_CONTEXT") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class PeCoffLoaderImageContextImageAddressField extends Field {
  PeCoffLoaderImageContextImageAddressField() {
    this.getDeclaringType().getUnderlyingType() instanceof PeCoffLoaderImageContextStruct and
    this.hasName("ImageAddress")
  }
}

/**
 * Header reinterpret-cast bridge for the loader's pointer arithmetic on
 * `ImageContext->ImageAddress`.
 *
 * The loader walks the loaded image through expressions like
 *
 * ```c
 * Hdr.Pe32     = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageContext->ImageAddress
 *                                            + ImageContext->PeCoffHeaderOffset);
 * FirstSection = (EFI_IMAGE_SECTION_HEADER *)((UINTN)ImageContext->ImageAddress
 *                                              + sizeof (EFI_TE_IMAGE_HEADER));
 * ```
 *
 * CodeQL's IR-based dataflow tracks pointer-arithmetic aliasing for pure
 * pointer forms like `(UINT8 *)p + N`, but loses it across the
 * intermediate `(UINTN)` cast: the addition becomes plain integer math
 * and the resulting pointer becomes an unrelated alias class, so reads
 * through `Hdr.Pe32`, `FirstSection`, etc. no longer alias the bytes at
 * `*ImageContext->ImageAddress`.
 *
 * Bridge the gap directly between struct content: from the indirect of
 * the `ImageContext` qualifier (`*ImageContext`) to the indirect of any
 * enclosing pointer-cast result. This skips the `ImageContext->ImageAddress`
 * field read entirely — desirable because the field's scalar value is a
 * pointer-as-integer that frequently appears in benign sizing arithmetic
 * (`(UINTN)ImageContext->ImageAddress + sizeof (EFI_TE_IMAGE_HEADER)`),
 * which would otherwise produce false-positive overflow alerts. The
 * field-content models in `lib/MdePkg/PeImage.qll` then carry the taint down
 * from the cast's pointee (`*Hdr` / `*Section`) to the scalar fields the
 * loader reads; `efiImageSectionHeaderMiscUnionStep` bridges the
 * intermediate anonymous-union value on the section header.
 */
predicate peCoffLoaderImageContextFieldWriteStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(FieldAccess imgAddrFa, Expr ancestor, Cast cast, FieldAccess hdrFa |
    imgAddrFa.getTarget() instanceof PeCoffLoaderImageContextImageAddressField and
    ancestor = imgAddrFa.getParent+() and
    cast = ancestor.getFullyConverted() and
    cast.getType().getUnspecifiedType() instanceof PointerType and
    hdrFa.getEnclosingFunction() = imgAddrFa.getEnclosingFunction() and
    hdrFa.getQualifier().getType().getUnspecifiedType() = cast.getType().getUnspecifiedType() and
    node1.asIndirectExpr() = imgAddrFa.getQualifier() and
    node2.asIndirectExpr() = hdrFa.getQualifier()
  )
}

/**
 * Holds if `call` invokes a `PE_COFF_LOADER_READ_FILE` callback. Three
 * shapes:
 *  - indirect call through a `FieldAccess` named `ImageRead` — covers the
 *    EDK II idiom `ImageContext->ImageRead(...)` at any depth and
 *    regardless of intermediate qualifiers;
 *  - indirect call through a function-pointer expression whose static
 *    type resolves to the `PE_COFF_LOADER_READ_FILE` typedef;
 *  - direct call to a function whose address is assigned into an
 *    `ImageRead` field anywhere in the program (e.g.
 *    `Image->ImageContext.ImageRead = CoreReadImageFile`).
 */
predicate isPeCoffLoaderReadFileCall(Call call) {
  exists(ExprCall ec | ec = call |
    ec.getExpr().(FieldAccess).getTarget().hasName("ImageRead")
    or
    ec.getExpr().getType().(TypedefType).hasName("PE_COFF_LOADER_READ_FILE")
    or
    ec.getExpr().getFullyConverted().getType().(TypedefType).hasName("PE_COFF_LOADER_READ_FILE")
  )
  or
  exists(Function f, Assignment a, FieldAccess fa, FunctionAccess fac |
    call.(FunctionCall).getTarget() = f and
    a.getLValue() = fa and
    fa.getTarget().hasName("ImageRead") and
    fac = a.getRValue().getFullyConverted() and
    fac.getTarget() = f
  )
}

/**
 * The bytes pointed-to by the `Buffer` argument of a
 * `PE_COFF_LOADER_READ_FILE` call. After the call returns, this memory
 * holds attacker-controlled image content.
 *
 * Modeling the source at the callback — rather than upstream at
 * `CoreLoadImage` — keeps the taint provenance tight to the actual
 * file-controlled data and avoids spuriously tainting `CoreLoadImage`
 * parameters that are not part of the image (`BootPolicy`, the parent
 * handle, etc.).
 *
 * The `PE_COFF_LOADER_READ_FILE` callback prototype:
 *
 * ```c
 * typedef RETURN_STATUS (EFIAPI *PE_COFF_LOADER_READ_FILE)(
 *   IN     VOID  *FileHandle,
 *   IN     UINTN  FileOffset,
 *   IN OUT UINTN *ReadSize,
 *   OUT    VOID  *Buffer);
 * ```
 */
class Edk2PeCoffLoaderReadFileSource extends FS::RemoteFlowSource {
  Edk2PeCoffLoaderReadFileSource() {
    exists(Call call |
      isPeCoffLoaderReadFileCall(call) and
      this.asIndirectExpr() = call.getArgument(3)
    )
  }

  override string getSourceType() {
    result = "data read from PE/COFF image via PE_COFF_LOADER_READ_FILE callback"
  }
}

/**
 * Bridges the buffer alias gap at the `ImageRead` call site within a
 * function.
 *
 * The Buffer argument of an `ImageRead` call is typically written as
 * `(VOID *)(UINTN)ImageContext->ImageAddress` — the loader uses the
 * loaded-image buffer's own base address as the read destination. The
 * `(UINTN)` cast collapses the pointer to an integer and back, which
 * causes CodeQL's IR-based dataflow to lose the alias between the
 * `Buffer` indirection and the `ImageContext->ImageAddress` indirection
 * even though both refer to the same memory region.
 *
 * Restore the alias by emitting a step from the indirect of the Buffer
 * arg (the bytes loaded by the call) to the post-update version of the
 * indirect of the qualifier expression of any `ImageAddress` field
 * access reachable inside the Buffer argument. Both the immediate
 * qualifier and any nested `VariableAccess` descendants are anchored,
 * so idioms like `Image->ImageContext.ImageAddress` flow correctly.
 * Once the `ImageContext` pointee is tainted at the
 * `PE_COFF_LOADER_READ_FILE` callback site, two downstream mechanisms
 * carry the taint onwards:
 *  - parameter-out flow on the `ImageContext` pointer propagates the
 *    post-update across the call boundary into any caller of the
 *    enclosing function, so no separate post-call source is needed;
 *  - `peCoffLoaderImageContextFieldWriteStep` bridges the `(UINTN)`
 *    cast to the pointee of the reinterpret-cast image-header pointer
 *    (`*Hdr`, `*Section`).
 */
predicate peCoffLoaderReadFileBufferStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Call call, FieldAccess imgAddrFa, Expr anchor |
    isPeCoffLoaderReadFileCall(call) and
    imgAddrFa.getEnclosingElement*() = call.getArgument(3) and
    imgAddrFa.getTarget().hasName("ImageAddress") and
    imgAddrFa.getTarget().getDeclaringType().getUnderlyingType() instanceof
      PeCoffLoaderImageContextStruct and
    (
      anchor = imgAddrFa.getQualifier()
      or
      anchor = imgAddrFa.getQualifier().getAChild+().(VariableAccess)
    ) and
    node1.asIndirectExpr() = call.getArgument(3) and
    node2.(DataFlow::PostUpdateNode).getPreUpdateNode().asIndirectExpr() = anchor
  )
}
