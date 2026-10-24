/**
 * Stub declarations for all EDK2 BaseLib string services modeled in
 * BaseLibString.qll.  This file is compiled into a CodeQL database so
 * that the introspection query can find each function and verify its modeled
 * properties.
 *
 * Only the type/signature information matters here; bodies are empty stubs.
 */

// ---- Minimal EDK2 type stubs ----
typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long   UINTN;
typedef unsigned long long UINT64;
typedef char            CHAR8;
typedef unsigned short  CHAR16;
typedef long            INTN;
typedef long long       INT64;
typedef unsigned long   RETURN_STATUS;
typedef void            VOID;

typedef struct { UINT8 Addr[16]; } IPv6_ADDRESS;
typedef struct { UINT8 Addr[4];  } IPv4_ADDRESS;
typedef struct {
  unsigned int Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8];
} GUID;

// ---- Group 1 & 2: StrLen / StrSize ----
UINTN  StrLen(const CHAR16 *String);
UINTN  AsciiStrLen(const CHAR8 *String);
UINTN  StrSize(const CHAR16 *String);
UINTN  AsciiStrSize(const CHAR8 *String);

// ---- Group 3: Bounded strlen / strsize ----
UINTN  StrnLenS(const CHAR16 *String, UINTN MaxSize);
UINTN  StrnSizeS(const CHAR16 *String, UINTN MaxSize);
UINTN  AsciiStrnLenS(const CHAR8 *String, UINTN MaxSize);
UINTN  AsciiStrnSizeS(const CHAR8 *String, UINTN MaxSize);

// ---- Group 4 & 5: StrCmp / AsciiStriCmp ----
INTN   StrCmp(const CHAR16 *FirstString, const CHAR16 *SecondString);
INTN   AsciiStrCmp(const CHAR8 *FirstString, const CHAR8 *SecondString);
INTN   AsciiStriCmp(const CHAR8 *FirstString, const CHAR8 *SecondString);

// ---- Group 6: Bounded strncmp ----
INTN   StrnCmp(const CHAR16 *FirstString, const CHAR16 *SecondString, UINTN Length);
INTN   AsciiStrnCmp(const CHAR8 *FirstString, const CHAR8 *SecondString, UINTN Length);

// ---- Group 7: StrStr / AsciiStrStr ----
CHAR16 *StrStr(const CHAR16 *String, const CHAR16 *SearchString);
CHAR8  *AsciiStrStr(const CHAR8 *String, const CHAR8 *SearchString);

// ---- Group 8: StrCpyS / AsciiStrCpyS ----
RETURN_STATUS  StrCpyS(CHAR16 *Destination, UINTN DestMax, const CHAR16 *Source);
RETURN_STATUS  AsciiStrCpyS(CHAR8 *Destination, UINTN DestMax, const CHAR8 *Source);

// ---- Group 9: StrnCpyS / AsciiStrnCpyS ----
RETURN_STATUS  StrnCpyS(CHAR16 *Destination, UINTN DestMax, const CHAR16 *Source, UINTN Length);
RETURN_STATUS  AsciiStrnCpyS(CHAR8 *Destination, UINTN DestMax, const CHAR8 *Source, UINTN Length);

// ---- Group 10: StrCatS / AsciiStrCatS ----
RETURN_STATUS  StrCatS(CHAR16 *Destination, UINTN DestMax, const CHAR16 *Source);
RETURN_STATUS  AsciiStrCatS(CHAR8 *Destination, UINTN DestMax, const CHAR8 *Source);

// ---- Group 11: StrnCatS / AsciiStrnCatS ----
RETURN_STATUS  StrnCatS(CHAR16 *Destination, UINTN DestMax, const CHAR16 *Source, UINTN Length);
RETURN_STATUS  AsciiStrnCatS(CHAR8 *Destination, UINTN DestMax, const CHAR8 *Source, UINTN Length);

// ---- Group 12: Full Unicode<->ASCII conversions ----
RETURN_STATUS  UnicodeStrToAsciiStrS(const CHAR16 *Source, CHAR8 *Destination, UINTN DestMax);
RETURN_STATUS  AsciiStrToUnicodeStrS(const CHAR8 *Source, CHAR16 *Destination, UINTN DestMax);

// ---- Group 13: Bounded Unicode<->ASCII conversions ----
RETURN_STATUS  UnicodeStrnToAsciiStrS(const CHAR16 *Source, UINTN Length,
                                       CHAR8 *Destination, UINTN DestMax,
                                       UINTN *DestinationLength);
RETURN_STATUS  AsciiStrnToUnicodeStrS(const CHAR8 *Source, UINTN Length,
                                       CHAR16 *Destination, UINTN DestMax,
                                       UINTN *DestinationLength);

// ---- Group 14: String-to-integer, Unicode legacy ----
UINTN   StrDecimalToUintn(const CHAR16 *String);
UINT64  StrDecimalToUint64(const CHAR16 *String);
UINTN   StrHexToUintn(const CHAR16 *String);
UINT64  StrHexToUint64(const CHAR16 *String);

// ---- Group 14: String-to-integer, Unicode safe ----
RETURN_STATUS  StrDecimalToUintnS(const CHAR16 *String, CHAR16 **EndPointer, UINTN *Data);
RETURN_STATUS  StrDecimalToUint64S(const CHAR16 *String, CHAR16 **EndPointer, UINT64 *Data);
RETURN_STATUS  StrHexToUintnS(const CHAR16 *String, CHAR16 **EndPointer, UINTN *Data);
RETURN_STATUS  StrHexToUint64S(const CHAR16 *String, CHAR16 **EndPointer, UINT64 *Data);

// ---- Group 15: String-to-integer, ASCII legacy ----
UINTN   AsciiStrDecimalToUintn(const CHAR8 *String);
UINT64  AsciiStrDecimalToUint64(const CHAR8 *String);
UINTN   AsciiStrHexToUintn(const CHAR8 *String);
UINT64  AsciiStrHexToUint64(const CHAR8 *String);

// ---- Group 15: String-to-integer, ASCII safe ----
RETURN_STATUS  AsciiStrDecimalToUintnS(const CHAR8 *String, CHAR8 **EndPointer, UINTN *Data);
RETURN_STATUS  AsciiStrDecimalToUint64S(const CHAR8 *String, CHAR8 **EndPointer, UINT64 *Data);
RETURN_STATUS  AsciiStrHexToUintnS(const CHAR8 *String, CHAR8 **EndPointer, UINTN *Data);
RETURN_STATUS  AsciiStrHexToUint64S(const CHAR8 *String, CHAR8 **EndPointer, UINT64 *Data);

// ---- Group 16: Structured-string parsers, Unicode ----
RETURN_STATUS  StrToIpv6Address(const CHAR16 *String, CHAR16 **EndPointer,
                                 IPv6_ADDRESS *Address, UINT8 *PrefixLength);
RETURN_STATUS  StrToIpv4Address(const CHAR16 *String, CHAR16 **EndPointer,
                                 IPv4_ADDRESS *Address, UINT8 *PrefixLength);
RETURN_STATUS  StrToGuid(const CHAR16 *String, GUID *Guid);

// ---- Group 17: Structured-string parsers, ASCII ----
RETURN_STATUS  AsciiStrToIpv6Address(const CHAR8 *String, CHAR8 **EndPointer,
                                      IPv6_ADDRESS *Address, UINT8 *PrefixLength);
RETURN_STATUS  AsciiStrToIpv4Address(const CHAR8 *String, CHAR8 **EndPointer,
                                      IPv4_ADDRESS *Address, UINT8 *PrefixLength);
RETURN_STATUS  AsciiStrToGuid(const CHAR8 *String, GUID *Guid);

// ---- Group 18: Hex-string to byte-array ----
RETURN_STATUS  StrHexToBytes(const CHAR16 *String, UINTN Length,
                              UINT8 *Buffer, UINTN MaxBufferSize);
RETURN_STATUS  AsciiStrHexToBytes(const CHAR8 *String, UINTN Length,
                                   UINT8 *Buffer, UINTN MaxBufferSize);

// ---- Group 19: Single-character case conversion ----
CHAR16  CharToUpper(CHAR16 Char);
CHAR8   AsciiCharToUpper(CHAR8 Chr);

// ---- Group 20: Base64 encode / decode ----
RETURN_STATUS  Base64Encode(const UINT8 *Source, UINTN SourceLength,
                             CHAR8 *Destination, UINTN *DestinationSize);
RETURN_STATUS  Base64Decode(const CHAR8 *Source, UINTN SourceSize,
                             UINT8 *Destination, UINTN *DestinationSize);
