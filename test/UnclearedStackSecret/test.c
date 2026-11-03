// Test cases for UnclearedStackSecret.ql.
//
// The query finds stack buffers whose address reaches a secret parameter
// (`isSecretParameter`, e.g. the Password of Pkcs5HashPassword) when some path
// to the function's return skips clearing them. `*_BAD` functions reproduce
// UserAuthFeaturePkg SmmPasswordHandler before 622a9d76ae and variants;
// `*_GOOD` functions clear the buffer on every path, or hold no secret.

typedef unsigned char   UINT8;
typedef unsigned long   UINTN;
typedef UINTN           EFI_STATUS;
typedef unsigned char   BOOLEAN;
typedef char            CHAR8;
typedef void            VOID;

#define NULL  ((VOID *)0)
#define EFI_SECURITY_VIOLATION  0x800000000000001A

typedef struct {
  UINTN    PasswordLen;
  CHAR8    OldPassword[32];
  CHAR8    NewPassword[32];
} SET_PASSWORD;

BOOLEAN
Pkcs5HashPassword (
  UINTN        PasswordLength,
  const CHAR8  *Password,
  UINTN        SaltLength,
  const UINT8  *Salt,
  UINTN        IterationCount,
  UINTN        DigestSize,
  UINTN        KeyLength,
  UINT8        *OutKey
  );

VOID  *ZeroMem (VOID *Buffer, UINTN Length);
VOID  *SetMem (VOID *Buffer, UINTN Length, UINT8 Value);
VOID  *CopyMem (VOID *DestinationBuffer, const VOID *SourceBuffer, UINTN Length);
VOID  SaveHash (UINT8 *Hash);

// KeyLibGeneratePBKDF2Hash-like helper; its Salt local is not a secret.
BOOLEAN
HashPassword (
  CHAR8  *Password,
  UINTN  PasswordSize,
  UINT8  *Hash
  )
{
  UINT8  Salt[16];

  SetMem (Salt, sizeof (Salt), 0x5A);
  return Pkcs5HashPassword (PasswordSize, Password, sizeof (Salt), Salt, 1000, 32, 32, Hash);
}

BOOLEAN
IsPasswordVerified (
  CHAR8  *Password,
  UINTN  PasswordSize
  )
{
  UINT8  Hash[32];

  return HashPassword (Password, PasswordSize, Hash);
}

//
// ---- BAD ----
//

// SmmPasswordHandler before 622a9d76ae: no path clears the copied passwords.
EFI_STATUS
PasswordHandler_BAD (
  VOID  *CommBuffer
  )
{
  EFI_STATUS    Status;
  SET_PASSWORD  SetPassword;
  UINT8         Hash[32];

  Status = 0;
  CopyMem (&SetPassword, CommBuffer, sizeof (SetPassword));
  if (!IsPasswordVerified (SetPassword.OldPassword, SetPassword.PasswordLen)) {
    Status = EFI_SECURITY_VIOLATION;
    goto EXIT;
  }

  HashPassword (SetPassword.NewPassword, SetPassword.PasswordLen, Hash);
  SaveHash (Hash);

EXIT:
  return Status;
}

// Cleared on the success path, but the early return skips the clear.
EFI_STATUS
EarlyReturn_BAD (
  VOID  *CommBuffer
  )
{
  CHAR8  Password[32];

  CopyMem (Password, CommBuffer, sizeof (Password));
  if (!IsPasswordVerified (Password, sizeof (Password))) {
    return EFI_SECURITY_VIOLATION;
  }

  ZeroMem (Password, sizeof (Password));
  return 0;
}

// Direct consumer call through an intermediate pointer.
VOID
DirectHash_BAD (
  VOID  *CommBuffer
  )
{
  CHAR8  Pin[16];
  CHAR8  *PinPtr;
  UINT8  Hash[32];

  CopyMem (Pin, CommBuffer, sizeof (Pin));
  PinPtr = Pin;
  Pkcs5HashPassword (sizeof (Pin), PinPtr, 0, NULL, 1000, 32, 32, Hash);
  SaveHash (Hash);
}

//
// ---- GOOD ----
//

// SmmPasswordHandler after 622a9d76ae: cleared at EXIT, which every path reaches.
EFI_STATUS
PasswordHandler_GOOD (
  VOID  *CommBuffer
  )
{
  EFI_STATUS    Status;
  SET_PASSWORD  SetPassword;
  UINT8         Hash[32];

  Status = 0;
  CopyMem (&SetPassword, CommBuffer, sizeof (SetPassword));
  if (!IsPasswordVerified (SetPassword.OldPassword, SetPassword.PasswordLen)) {
    Status = EFI_SECURITY_VIOLATION;
    goto EXIT;
  }

  HashPassword (SetPassword.NewPassword, SetPassword.PasswordLen, Hash);
  SaveHash (Hash);

EXIT:
  ZeroMem (&SetPassword, sizeof (SetPassword));
  return Status;
}

// Cleared with SetMem (..., 0) on both paths.
EFI_STATUS
SetMemClear_GOOD (
  VOID  *CommBuffer
  )
{
  CHAR8  Password[32];

  CopyMem (Password, CommBuffer, sizeof (Password));
  if (!IsPasswordVerified (Password, sizeof (Password))) {
    SetMem (Password, sizeof (Password), 0);
    return EFI_SECURITY_VIOLATION;
  }

  SetMem (Password, sizeof (Password), 0);
  return 0;
}
