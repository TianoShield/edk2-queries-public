// Test cases for TaintedUnguardedOffsetRead.ql.
//
// The query tracks attacker-controlled bytes (read through the `mImageBase`
// global) to a constant positive-offset read `*(p + k)` / `p[k]` that is
// neither dominated by a local guard ensuring the buffer length exceeds `k`,
// nor gated by a minimum-length validator call that rejects too-short buffers.
// `*_BAD` functions reproduce an out-of-bounds read (CVE-2024-38797 image
// shape, CVE-2023-45231 option-validator shape); `*_GOOD` functions add the
// fix's length guard / validator, or use a non-attacker buffer.

typedef unsigned char        UINT8;
typedef unsigned short       UINT16;
typedef unsigned int         UINT32;
typedef unsigned long        UINTN;
typedef unsigned long        EFI_STATUS;
typedef unsigned char        BOOLEAN;
typedef void                 VOID;
typedef char                 CHAR8;

#define TWO_BYTE_ENCODE  0x82
#define TRUE             ((BOOLEAN)(1 == 1))
#define FALSE            ((BOOLEAN)(0 == 1))

typedef struct {
  UINT32    dwLength;
  UINT16    wRevision;
  UINT16    wCertificateType;
} WIN_CERTIFICATE;

// Trailing one-element flexible array buffer, as in SecurityPkg.
typedef struct {
  WIN_CERTIFICATE    Hdr;
  UINT8              CertData[1];
} WIN_CERTIFICATE_EFI_PKCS;

// The image being verified. Modeled as the attacker-controlled source.
UINT8   *mImageBase = 0;

// Attacker-influenced offset/size fields parsed from the image header.
UINT32  mOffset    = 0;
UINTN   mCertSize  = 0;

UINTN   CompareMem (const VOID *a, const VOID *b, UINTN len);

//
// ---- BAD: unguarded constant-offset reads of attacker-controlled bytes ----
//

// Flow like SecureBootConfigImpl.c: struct field CertData straight off
// mImageBase, second byte read with no length guard.
EFI_STATUS
HashField_BAD (
  VOID
  )
{
  WIN_CERTIFICATE_EFI_PKCS  *Pkcs;

  Pkcs = (WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mOffset);
  if ((*(Pkcs->CertData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
    return 1;
  }

  return 0;
}

// Flow like DxeImageVerificationLib.c: the certificate pointer is passed to a
// helper, which reads the second byte unguarded.
EFI_STATUS
HashByType_Param_BAD (
  UINT8  *AuthData,
  UINTN  AuthDataSize
  )
{
  if ((*(AuthData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
    return 1;
  }

  return 0;
}

VOID
HashCaller_BAD (
  VOID
  )
{
  WIN_CERTIFICATE_EFI_PKCS  *Pkcs;
  UINT8                     *AuthData;

  Pkcs     = (WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mOffset);
  AuthData = Pkcs->CertData;
  HashByType_Param_BAD (AuthData, mCertSize);
}

// Mutation: array-index form `p[1]` instead of `*(p + 1)`, no struct.
EFI_STATUS
HashArrayIndex_BAD (
  VOID
  )
{
  UINT8  *Cert;

  Cert = (UINT8 *)(mImageBase + mOffset);
  if ((Cert[1] & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
    return 1;
  }

  return 0;
}

// Mutation: base read straight from mImageBase via an intermediate pointer,
// larger constant offset.
EFI_STATUS
HashOffset2_BAD (
  VOID
  )
{
  UINT8  *Cert;
  UINT8  *P;

  Cert = mImageBase;
  P    = Cert;
  if ((*(P + 2) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
    return 1;
  }

  return 0;
}

//
// ---- GOOD: length-guarded reads (the fix) and non-attacker buffers ----
//

// Fix shape: short-circuit `(Size > 1) && *(p + 1)`.
EFI_STATUS
HashGuardedShortCircuit_GOOD (
  VOID
  )
{
  WIN_CERTIFICATE_EFI_PKCS  *Pkcs;
  UINTN                     CertSize;

  Pkcs     = (WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mOffset);
  CertSize = mCertSize;
  if ((CertSize > 1) && ((*(Pkcs->CertData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE)) {
    return 1;
  }

  return 0;
}

// Fix shape: enclosing `if (Size > 1) { ... }` block guard.
EFI_STATUS
HashBlockGuard_GOOD (
  VOID
  )
{
  WIN_CERTIFICATE_EFI_PKCS  *Pkcs;
  UINTN                     CertSize;

  Pkcs     = (WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mOffset);
  CertSize = mCertSize;
  if (CertSize > 1) {
    if ((*(Pkcs->CertData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
      return 1;
    }
  }

  return 0;
}

// Equivalent guard written as `Size >= 2`.
EFI_STATUS
HashGuardGe2_GOOD (
  UINT8  *AuthData,
  UINTN  AuthDataSize
  )
{
  if (AuthDataSize >= 2) {
    if ((*(AuthData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
      return 1;
    }
  }

  return 0;
}

VOID
HashGuardGe2Caller_GOOD (
  VOID
  )
{
  WIN_CERTIFICATE_EFI_PKCS  *Pkcs;

  Pkcs = (WIN_CERTIFICATE_EFI_PKCS *)(mImageBase + mOffset);
  HashGuardGe2_GOOD (Pkcs->CertData, mCertSize);
}

// Not attacker-controlled: a local buffer, no flow from mImageBase.
EFI_STATUS
HashLocalBuffer_GOOD (
  VOID
  )
{
  UINT8  LocalBuf[64];
  UINT8  *P;

  P = LocalBuf;
  if ((*(P + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) {
    return 1;
  }

  return 0;
}

//
// ---- Validator-gated option reads (CVE-2023-45231 shape) ----
//
// `Ip6ProcessRedirect` reads the second byte of an option header only after
// `if (!Ip6IsNDOptionValid (Option, OptionLen)) goto Exit;`. The fix makes
// that validator reject buffers shorter than one header; reverting it leaves
// the `*(Option + 1)` read reachable for a single-byte option.
//

// A two-byte option header, like IP6_OPTION_HEADER.
typedef struct {
  UINT8    Type;
  UINT8    Length;
} OPTION_HEADER;

// Minimum-length validator: rejects buffers too short to hold a header.
// Mirrors the patched Ip6IsNDOptionValid.
BOOLEAN
ValidateMinLen (
  UINT8   *Option,
  UINT16  OptionLen
  )
{
  if (OptionLen < sizeof (OPTION_HEADER)) {
    return FALSE;
  }

  return TRUE;
}

// Validator that does not enforce a minimum length (only inspects a content
// byte). Mirrors the reverted, vulnerable Ip6IsNDOptionValid.
BOOLEAN
ValidateNoMinLen (
  UINT8   *Option,
  UINT16  OptionLen
  )
{
  if (Option[0] == 0) {
    return FALSE;
  }

  return TRUE;
}

// GOOD: the second-byte read is dominated by a minimum-length validator call.
EFI_STATUS
RedirectValidated_GOOD (
  VOID
  )
{
  UINT8   *Option;
  UINT16  OptionLen;

  Option    = (UINT8 *)(mImageBase + mOffset);
  OptionLen = (UINT16)mCertSize;
  if (!ValidateMinLen (Option, OptionLen)) {
    return 1;
  }

  if (*(Option + 1) == 0) {
    return 1;
  }

  return 0;
}

// BAD: a validator runs but never rejects too-short buffers, so the
// second-byte read is still out of bounds for a single-byte option.
EFI_STATUS
RedirectValidatedNoMinLen_BAD (
  VOID
  )
{
  UINT8   *Option;
  UINT16  OptionLen;

  Option    = (UINT8 *)(mImageBase + mOffset);
  OptionLen = (UINT16)mCertSize;
  if (!ValidateNoMinLen (Option, OptionLen)) {
    return 1;
  }

  if (*(Option + 1) == 0) {
    return 1;
  }

  return 0;
}

// GOOD: the validated pointer and the dereferenced pointer differ but both
// derive from the attacker source; the minimum-length validator still
// dominates the read. Mirrors Ip6ProcessRedirect re-deriving `Option`.
EFI_STATUS
RedirectValidatedReDerived_GOOD (
  VOID
  )
{
  UINT8   *Validated;
  UINT8   *Option;
  UINT16  OptionLen;

  Validated = (UINT8 *)(mImageBase + mOffset);
  OptionLen = (UINT16)mCertSize;
  if (!ValidateMinLen (Validated, OptionLen)) {
    return 1;
  }

  Option = (UINT8 *)(mImageBase + mOffset + 4);
  if (*(Option + 1) == 0) {
    return 1;
  }

  return 0;
}
