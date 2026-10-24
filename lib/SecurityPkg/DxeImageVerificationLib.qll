/**
 * Shared models for EDK2 image authentication in
 * `SecurityPkg/Library/DxeImageVerificationLib/DxeImageVerificationLib.c`
 * and `SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigImpl.c`.
 *
 * Both translation units verify a PE/COFF image whose bytes live in the
 * file-scope global `mImageBase` (`UINT8 *`). In `DxeImageVerificationLib`
 * `mImageBase` is the `FileBuffer` handed to the registered
 * `EFI_SECURITY2_FILE_AUTHENTICATION_HANDLER`; in `SecureBootConfigImpl` it is
 * the buffer filled by `ReadFileContent` from a user-selected file. In both
 * cases the image being verified is attacker-controlled (that is the secure
 * boot threat model), so reads of `mImageBase` yield attacker-controlled
 * bytes.
 *
 * Provides:
 *  - a flow source for the pointee bytes obtained when reading `mImageBase`;
 *  - a `TaintInheritingContent` carrying taint from a `WIN_CERTIFICATE*` struct
 *    into the bytes of its trailing `CertData[]` member, which the Authenticode
 *    parsing reads via `X->CertData`.
 */

import cpp
private import semmle.code.cpp.security.FlowSources as FS
private import semmle.code.cpp.dataflow.new.DataFlow
private import semmle.code.cpp.ir.dataflow.FlowSteps

/**
 * The verified-image base pointer `mImageBase` (`UINT8 *`), a file-scope
 * global in both `DxeImageVerificationLib.c` and `SecureBootConfigImpl.c`.
 */
class VerifiedImageBaseVariable extends GlobalOrNamespaceVariable {
  VerifiedImageBaseVariable() {
    this.hasName("mImageBase") and
    this.getType().getUnspecifiedType() instanceof PointerType
  }
}

/**
 * The attacker-controlled bytes read through the verified-image base pointer
 * `mImageBase`. The source is the indirection (`*mImageBase`) of any read
 * access, so taint seeds the image buffer contents wherever the verification
 * code dereferences the base — e.g. `(WIN_CERTIFICATE *)(mImageBase + OffSet)`
 * and `(WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mSecDataDir->Offset)`.
 *
 * Modeling the source at `mImageBase` (rather than upstream at `FileBuffer` /
 * `ReadFileContent`) keeps the taint intra-procedural with the offset reads it
 * feeds and avoids depending on flow through the `mImageBase` global across
 * function boundaries (the `SecureBootConfigImpl` sink reads the global in a
 * different function from where it is filled).
 */
class Edk2VerifiedImageBaseSource extends FS::RemoteFlowSource {
  Edk2VerifiedImageBaseSource() {
    exists(VariableAccess va |
      va.getTarget() instanceof VerifiedImageBaseVariable and
      // exclude the write side (`mImageBase = ...`, `&mImageBase`); only reads
      // of the pointer yield image bytes through their indirection.
      not exists(Assignment a | a.getLValue() = va) and
      not va.getParent() instanceof AddressOfExpr and
      this.asIndirectExpr() = va
    )
  }

  override string getSourceType() {
    result = "PE/COFF image being verified by SecurityPkg (mImageBase)"
  }
}

/**
 * The trailing variable-length `CertData[]` byte buffer of a `WIN_CERTIFICATE`
 * family struct, declared as a one-element flexible array, e.g.
 *
 * ```c
 * typedef struct {
 *   WIN_CERTIFICATE Hdr;
 *   UINT8           CertData[1];
 * } WIN_CERTIFICATE_EFI_PKCS;
 * ```
 *
 * (`WIN_CERTIFICATE_UEFI_GUID` has the same trailing `CertData[]`.)
 */
class WinCertificateCertDataField extends Field {
  WinCertificateCertDataField() {
    this.hasName("CertData") and
    this.getUnspecifiedType() instanceof ArrayType
  }
}

/**
 * Taint on a `WIN_CERTIFICATE*` struct flows into the bytes of its trailing
 * `CertData[]` member: the array storage overlaps the struct content, so when
 * `*X` is attacker-controlled, so are the bytes read out of `X->CertData`. The
 * indirection index is 1 — taint applies to the pointee bytes reached through
 * the field, not to the field address itself. Mirrors the PE/COFF header field
 * models in `lib/MdePkg/PeImage.qll`.
 *
 * For a direct dereference `*(X->CertData + k)`, the read step taints the
 * dereferenced value straight from `*X` (the struct content): CodeQL's dataflow
 * has no intermediate node for the field-access indirection `*(X->CertData)`. A
 * sink therefore cannot match `node.asIndirectExpr()` for `X->CertData`; it must
 * match the loaded value, `node.asExpr()` for the deref, as
 * `TaintedImageUnguardedOffsetRead.ql` does.
 */
private class WinCertificateCertDataTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  WinCertificateCertDataTaintInheritingContent() {
    this.getField() instanceof WinCertificateCertDataField and
    this.getIndirectionIndex() = 1
  }
}
