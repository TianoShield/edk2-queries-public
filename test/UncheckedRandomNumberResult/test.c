// Test cases for UncheckedRandomNumberResult.ql.
//
// The query finds RNG calls (BaseCryptLib RandomBytes, RngLib
// GetRandomNumber*, EFI_RNG_PROTOCOL.GetRNG, and wrappers that fill a caller
// buffer and pass their result on) whose result is never tested outside an
// assertion. `*_BAD` functions reproduce UserAuthFeaturePkg KeyLibGenerateSalt
// before 04ba6e7c65 and variants; `*_GOOD` functions test or return the
// result, or ignore a result that does not report random data.

typedef unsigned char       UINT8;
typedef unsigned long long  UINT64;
typedef long                INTN;
typedef unsigned long       UINTN;
typedef UINTN               EFI_STATUS;
typedef unsigned char       BOOLEAN;
typedef void                VOID;

#define NULL   ((VOID *)0)
#define TRUE   ((BOOLEAN)(1 == 1))
#define FALSE  ((BOOLEAN)(0 == 1))

#define EFI_OUT_OF_RESOURCES  0x8000000000000009
#define EFI_NOT_READY         0x8000000000000006
#define EFI_ERROR(StatusCode)  (((INTN)(StatusCode)) < 0)

VOID  DebugAssert (const char *FileName, UINTN LineNumber, const char *Description);

#define ASSERT_EFI_ERROR(StatusParameter)                              \
  do {                                                                 \
    if (EFI_ERROR (StatusParameter)) {                                 \
      DebugAssert (__FILE__, __LINE__, "!EFI_ERROR (" #StatusParameter ")"); \
    }                                                                  \
  } while (0)

BOOLEAN  RandomSeed (const UINT8 *Seed, UINTN SeedSize);
BOOLEAN  RandomBytes (UINT8 *Output, UINTN Size);
BOOLEAN  GetRandomNumber64 (UINT64 *Rand);
BOOLEAN  GetRandomNumber128 (UINT64 *Rand);
VOID     *CopyMem (VOID *DestinationBuffer, const VOID *SourceBuffer, UINTN Length);

typedef struct _EFI_RNG_PROTOCOL EFI_RNG_PROTOCOL;

typedef EFI_STATUS (*EFI_RNG_GET_RNG)(
  EFI_RNG_PROTOCOL  *This,
  VOID              *RNGAlgorithm,
  UINTN             RNGValueLength,
  UINT8             *RNGValue
  );

struct _EFI_RNG_PROTOCOL {
  VOID               *GetInfo;
  EFI_RNG_GET_RNG    GetRNG;
};

VOID  UseKey (UINT8 *Key);

//
// ---- BAD ----
//

// KeyLibGenerateSalt before 04ba6e7c65: both results discarded.
BOOLEAN
GenerateSalt_BAD (
  UINT8  *SaltValue,
  UINTN  SaltSize
  )
{
  if (SaltValue == NULL) {
    return FALSE;
  }

  RandomSeed (NULL, 0);
  RandomBytes (SaltValue, SaltSize);
  return TRUE;
}

// The result is stored but never tested.
UINT64
Nonce_BAD (
  VOID
  )
{
  UINT64   Nonce;
  BOOLEAN  Ok;

  Ok = GetRandomNumber64 (&Nonce);
  return Nonce;
}

// The protocol status is only asserted, which compiles away in release builds.
VOID
ProtocolKey_BAD (
  EFI_RNG_PROTOCOL  *Rng,
  UINT8             *Key
  )
{
  EFI_STATUS  Status;

  Status = Rng->GetRNG (Rng, NULL, 32, Key);
  ASSERT_EFI_ERROR (Status);
  UseKey (Key);
}

// The wrapper passes its RNG result on, but this caller ignores it
// (SavePasswordToVariable before 04ba6e7c65).
BOOLEAN GenerateSalt_GOOD (UINT8 *SaltValue, UINTN SaltSize);

VOID
SavePassword_BAD (
  UINT8  *Salt
  )
{
  GenerateSalt_GOOD (Salt, 32);
  UseKey (Salt);
}

// RdRandGenerateEntropy-style wrapper: fills the caller's buffer from a local
// seed and returns an error when the RNG fails; this caller ignores it.
EFI_STATUS
FillEntropy (
  UINTN  Length,
  UINT8  *Entropy
  )
{
  UINT64  Seed[2];
  UINT8   *Ptr;

  Ptr = Entropy;
  if (!GetRandomNumber128 (Seed)) {
    return EFI_NOT_READY;
  }

  CopyMem (Ptr, Seed, Length);
  return 0;
}

VOID
SetPlatformAuth_BAD (
  UINT8  *Auth
  )
{
  FillEntropy (16, Auth);
  UseKey (Auth);
}

//
// ---- GOOD ----
//

// KeyLibGenerateSalt after 04ba6e7c65.
BOOLEAN
GenerateSalt_GOOD (
  UINT8  *SaltValue,
  UINTN  SaltSize
  )
{
  if (SaltValue == NULL) {
    return FALSE;
  }

  if (!RandomSeed (NULL, 0)) {
    return FALSE;
  }

  if (!RandomBytes (SaltValue, SaltSize)) {
    return FALSE;
  }

  return TRUE;
}

// SavePasswordToVariable after 04ba6e7c65.
EFI_STATUS
SavePassword_GOOD (
  UINT8  *Salt
  )
{
  BOOLEAN  SaltGenerated;

  SaltGenerated = GenerateSalt_GOOD (Salt, 32);
  if (!SaltGenerated) {
    return EFI_OUT_OF_RESOURCES;
  }

  UseKey (Salt);
  return 0;
}

// The protocol status is tested.
EFI_STATUS
ProtocolKey_GOOD (
  EFI_RNG_PROTOCOL  *Rng,
  UINT8             *Key
  )
{
  EFI_STATUS  Status;

  Status = Rng->GetRNG (Rng, NULL, 32, Key);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  UseKey (Key);
  return 0;
}

// The result is handed back to the caller.
BOOLEAN
Nonce_GOOD (
  UINT64  *Nonce
  )
{
  return GetRandomNumber64 (Nonce);
}

// Uses random data internally and fails when the RNG fails, but hands no
// random data back (SavePasswordToVariable after 04ba6e7c65). Ignoring its
// result is not an RNG problem.
EFI_STATUS
StoreHashedPassword (
  UINT8  *Password
  )
{
  UINT8  Salt[16];

  if (!GenerateSalt_GOOD (Salt, sizeof (Salt))) {
    return EFI_OUT_OF_RESOURCES;
  }

  UseKey (Salt);
  return 0;
}

VOID
ResetPassword_GOOD (
  VOID
  )
{
  StoreHashedPassword (NULL);
}

// Seeding has no output buffer; a failed seed makes the next RandomBytes fail.
VOID
ReseedOnly_GOOD (
  VOID
  )
{
  RandomSeed (NULL, 0);
}
