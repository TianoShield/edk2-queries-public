/**
 * Test cases for TaintedNullTerminatedStringFunction query (CWE-170).
 *
 * Tests that attacker-controlled data from UdpIoRecvDatagram callbacks is
 * tracked to functions that assume null-terminated input (AsciiStrLen,
 * StrLen, etc.), where a missing null terminator causes OOB read.
 */

#include "../include/NetBuffer.c"

typedef unsigned short  UINT16;
typedef int             INTN;
typedef UINTN           EFI_STATUS;
typedef char            CHAR8;
typedef unsigned short  CHAR16;

#define EFI_SUCCESS           0
#define EFI_INVALID_PARAMETER 2
#define EFI_BUFFER_TOO_SMALL  5
#define EFI_PROTOCOL_ERROR    7
#define EFI_OUT_OF_RESOURCES  9

typedef struct {
    int dummy;
} UDP_END_POINT;

typedef struct {
    int dummy;
} UDP_IO;

// ---- Stub function declarations ----

typedef VOID (*UDP_IO_CALLBACK)(NET_BUF *, UDP_END_POINT *, EFI_STATUS, VOID *);
EFI_STATUS UdpIoRecvDatagram(UDP_IO *UdpIo, UDP_IO_CALLBACK CallBack, VOID *Context, UINT32 HeadLen);

void *AllocatePool(UINTN Size);
void FreePool(void *Buffer);
void NetbufFree(NET_BUF *Nbuf);

// String functions requiring null termination (unbounded read)
UINTN AsciiStrLen(const CHAR8 *String);
UINTN StrLen(const CHAR16 *String);
INTN  AsciiStrCmp(const CHAR8 *FirstString, const CHAR8 *SecondString);
const CHAR8 *AsciiStrStr(const CHAR8 *String, const CHAR8 *SearchString);
UINTN AsciiStrDecimalToUintn(const CHAR8 *String);

// Print functions — format string must be null-terminated
UINTN AsciiPrint(const CHAR8 *Format, ...);
UINTN AsciiSPrint(CHAR8 *StartOfBuffer, UINTN BufferSize, const CHAR8 *FormatString, ...);

// Bounded string functions — safe to call with untrusted data
UINTN AsciiStrnLenS(const CHAR8 *String, UINTN MaxSize);

// Safe string functions — still interpret Source as null-terminated C string
EFI_STATUS AsciiStrCpyS(CHAR8 *Destination, UINTN DestMax, const CHAR8 *Source);

// ---- DNS-like structures for testing ----

#pragma pack(1)
typedef struct {
    UINT16 Identification;
    UINT16 Flags;
    UINT16 QuestionsNum;
    UINT16 AnswersNum;
    UINT16 AuthorityNum;
    UINT16 AditionalNum;
} DNS_HEADER;
#pragma pack()

// ---- Forward declarations and callback registration ----

VOID DnsOnPacketReceived(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NetbufCopy_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrCmp_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrStr_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestAsciiPrint_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestAsciiSPrint_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestAsciiStrCpyS_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestFormatSpecArg_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrCmp_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NetbufGetByte_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_ConstantString_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NullTerminated_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_FieldAccess_BAD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestAsciiStrnLenS_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NullTermGuard_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NullTermGuardEq_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NullTermGuardGetByte_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_NullTermGuardEqGetByte_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);
VOID TestStrLen_InterproceduralNullTermGuard_GOOD(NET_BUF *Packet, UDP_END_POINT *EndPoint, EFI_STATUS IoStatus, VOID *Context);

void register_callbacks(UDP_IO *UdpIo) {
    UdpIoRecvDatagram(UdpIo, DnsOnPacketReceived, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NetbufCopy_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NetbufGetByte_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_ConstantString_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NullTerminated_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_FieldAccess_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrCmp_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrCmp_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrStr_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestAsciiPrint_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestAsciiSPrint_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestAsciiStrCpyS_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestFormatSpecArg_BAD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestAsciiStrnLenS_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NullTermGuard_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NullTermGuardEq_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NullTermGuardGetByte_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_NullTermGuardEqGetByte_GOOD, (VOID *)0, 0);
    UdpIoRecvDatagram(UdpIo, TestStrLen_InterproceduralNullTermGuard_GOOD, (VOID *)0, 0);
}

// ---- Test: BAD - AsciiStrLen on NetbufGetByte result (DNS-like pattern) ----
// Mirrors DnsOnPacketReceived → ParseDnsResponse → AsciiStrLen(QueryName)

VOID
DnsOnPacketReceived(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  *RcvString;

    // NetbufGetByte returns a pointer directly into the packet buffer.
    // The data is attacker-controlled and may not be null-terminated.
    RcvString = (CHAR8 *)NetbufGetByte(Packet, 0, (UINT32 *)0);
    if (RcvString == (CHAR8 *)0) {
        return;
    }

    // BAD: AsciiStrLen scans for '\0' without a length bound.
    // If the packet data is not null-terminated, this reads out of bounds.
    UINTN QueryNameLen = AsciiStrLen(RcvString);

    (void)QueryNameLen;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrLen after NetbufCopy into local buffer ----

VOID
TestStrLen_NetbufCopy_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  RxBuf[512];
    CHAR8  *QueryName;

    // Copy raw packet bytes into local buffer. No null terminator guaranteed.
    NetbufCopy(Packet, 0, 256, RxBuf);

    QueryName = (CHAR8 *)RxBuf;

    // BAD: buffer may not contain a null terminator
    UINTN Len = AsciiStrLen(QueryName);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrLen on NetbufGetByte with pointer arithmetic ----

VOID
TestStrLen_NetbufGetByte_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  *RawData;

    RawData = NetbufGetByte(Packet, sizeof(DNS_HEADER), (UINT32 *)0);
    if (RawData == (UINT8 *)0) {
        return;
    }

    // BAD: treating raw packet bytes as a C string
    UINTN Len = AsciiStrLen((CHAR8 *)RawData);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: GOOD - AsciiStrLen on a constant string ----
// The packet data is received but not passed to AsciiStrLen.

VOID
TestStrLen_ConstantString_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8 *SafeString = "hello.example.com";

    // GOOD: AsciiStrLen on a constant string literal, not packet data
    UINTN Len = AsciiStrLen(SafeString);  // Safe

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: GOOD - AsciiStrLen after explicit null termination ----
// The buffer has a null terminator forced at the end.

VOID
TestStrLen_NullTerminated_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  RxBuf[512];
    UINT32 CopyLen;

    CopyLen = NetbufCopy(Packet, 0, 255, RxBuf);

    // Force null termination before calling AsciiStrLen
    RxBuf[CopyLen] = 0;

    // GOOD: buffer is guaranteed null-terminated
    UINTN Len = AsciiStrLen((CHAR8 *)RxBuf);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrLen via struct field access ----
// Similar to DNS parsing where header fields point into packet data.

typedef struct {
    CHAR8  *Name;
    UINT16  Type;
    UINT16  Class;
} DNS_QUERY_SECTION;

typedef struct {
    UINT16 OpCode;
} OPTION_PACKET_HEADER;

typedef struct {
    CHAR8 *OptionStr;
    CHAR8 *ValueStr;
} OPTION_PAIR;

EFI_STATUS
ParseDelimitedPairs(
    OPTION_PACKET_HEADER *Packet,
    UINT32               PacketLen,
    UINT32               *Count,
    OPTION_PAIR          *Options
    )
{
    UINT8  *Cur;
    UINT8  *Last;
    UINT32 Num;
    CHAR8  *Name;
    CHAR8  *Value;

    if ((PacketLen <= sizeof(UINT16)) || (Packet == (OPTION_PACKET_HEADER *)0) || (Count == (UINT32 *)0)) {
        return EFI_INVALID_PARAMETER;
    }

    Cur = (UINT8 *)Packet + sizeof(UINT16);
    Last = (UINT8 *)Packet + PacketLen - 1;
    Num = 0;

    while (Cur < Last) {
        Name = (CHAR8 *)Cur;

        while (*Cur != 0) {
            Cur++;
        }

        if (Cur == Last) {
            return EFI_PROTOCOL_ERROR;
        }

        Cur++;
        Value = (CHAR8 *)Cur;

        while (*Cur != 0) {
            Cur++;
        }

        Num++;

        if ((Options != (OPTION_PAIR *)0) && (Num <= *Count)) {
            Options[Num - 1].OptionStr = Name;
            Options[Num - 1].ValueStr  = Value;
        }

        Cur++;
    }

    if ((*Count < Num) || (Options == (OPTION_PAIR *)0)) {
        *Count = Num;
        return EFI_BUFFER_TOO_SMALL;
    }

    *Count = Num;
    return EFI_SUCCESS;
}

EFI_STATUS
ParseDelimitedStart(
    OPTION_PACKET_HEADER *Packet,
    UINT32               PacketLen,
    UINT32               *OptionCount,
    OPTION_PAIR          **OptionList
    )
{
    EFI_STATUS Status;

    if ((Packet == (OPTION_PACKET_HEADER *)0) || (PacketLen == 0) || (OptionCount == (UINT32 *)0)) {
        return EFI_INVALID_PARAMETER;
    }

    *OptionCount = 0;

    if (OptionList != (OPTION_PAIR **)0) {
        *OptionList = (OPTION_PAIR *)0;
    }

    if (*((UINT8 *)Packet + PacketLen - 1) != 0) {
        return EFI_PROTOCOL_ERROR;
    }

    Status = ParseDelimitedPairs(Packet, PacketLen, OptionCount, (OPTION_PAIR *)0);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
    }

    if (OptionList == (OPTION_PAIR **)0) {
        return EFI_SUCCESS;
    }

    *OptionList = (OPTION_PAIR *)AllocatePool(*OptionCount * sizeof(OPTION_PAIR));
    if (*OptionList == (OPTION_PAIR *)0) {
        return EFI_OUT_OF_RESOURCES;
    }

    return ParseDelimitedPairs(Packet, PacketLen, OptionCount, *OptionList);
}

VOID
TestStrLen_FieldAccess_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  *RcvData;
    DNS_QUERY_SECTION QuerySection;

    RcvData = NetbufGetByte(Packet, 0, (UINT32 *)0);
    if (RcvData == (UINT8 *)0) {
        return;
    }

    // The Name pointer points into attacker-controlled packet data
    QuerySection.Name = (CHAR8 *)RcvData;

    // BAD: field derived from packet data, not null-terminated
    UINTN Len = AsciiStrLen(QuerySection.Name);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrCmp with tainted first argument ----
// Attacker controls the first string; if it has no null terminator,
// AsciiStrCmp scans past the buffer boundary.

VOID
TestStrCmp_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];

    NetbufCopy(Packet, 0, 255, (UINT8 *)RcvBuf);

    // BAD: RcvBuf comes from the network and may not be null-terminated
    INTN Cmp = AsciiStrCmp(RcvBuf, "expected-hostname");

    (void)Cmp;
    NetbufFree(Packet);
}

// ---- Test: GOOD - AsciiStrCmp with statically known first argument ----
// The first argument is a string literal; only the second is tainted, but it
// is always compared byte-by-byte and will not exceed the valid literal.
// (Note: the second arg is still tainted; if it also lacked a null terminator
// that would be a separate alert. Here we just verify the non-tainted arg
// path does not generate a spurious alert on the first parameter.)

VOID
TestStrCmp_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    // GOOD: Literal first argument is always null-terminated.
    // (Second arg taint would generate its own alert, which is correct.)
    INTN Cmp = AsciiStrCmp("literal-value", "another-literal");

    (void)Cmp;
    (void)Packet;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrStr with tainted haystack ----
// If the haystack has no null terminator, AsciiStrStr reads past the buffer.

VOID
TestStrStr_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[512];

    NetbufCopy(Packet, 0, 511, (UINT8 *)RcvBuf);

    // BAD: RcvBuf is attacker-controlled and may not be null-terminated
    const CHAR8 *Found = AsciiStrStr(RcvBuf, "\r\n");

    (void)Found;
    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiPrint with tainted format string ----
// If the format string is not null-terminated, AsciiPrint reads past it.
// (Also a format-string injection, but CWE-170 applies equally.)

VOID
TestAsciiPrint_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  FmtBuf[128];

    NetbufCopy(Packet, 0, 127, (UINT8 *)FmtBuf);

    // BAD: FmtBuf comes from the network — no null termination guaranteed
    AsciiPrint(FmtBuf);

    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiSPrint with tainted format string (param 2) ----

VOID
TestAsciiSPrint_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  FmtBuf[128];
    CHAR8  OutBuf[256];

    NetbufCopy(Packet, 0, 127, (UINT8 *)FmtBuf);

    // BAD: FmtBuf at param 2 comes from the network — no null termination guaranteed
    AsciiSPrint(OutBuf, sizeof(OutBuf), FmtBuf);

    NetbufFree(Packet);
}

// ---- Test: BAD - AsciiStrCpyS with tainted Source (param 2) ----
// The _s variant still interprets Source as a null-terminated C string.
// If Source lacks a null terminator and DestMax is wrong, the function may
// read OOB or invoke a runtime-constraint handler (DoS).

VOID
TestAsciiStrCpyS_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];
    CHAR8  DestBuf[256];

    NetbufCopy(Packet, 0, 255, (UINT8 *)RcvBuf);

    // BAD: RcvBuf comes from the network and may not be null-terminated.
    // AsciiStrCpyS still scans Source for '\0' — CWE-170 applies.
    AsciiStrCpyS(DestBuf, sizeof(DestBuf), RcvBuf);

    NetbufFree(Packet);
}

// ---- Test: BAD - tainted %s argument to AsciiSPrint with literal format ----
// The format string is a constant literal, so CodeQL can resolve the %s
// specifier.  The %s argument (RcvBuf) is attacker-controlled and may not
// be null-terminated; AsciiSPrint will scan it for '\0' to determine the
// string length before copying.

VOID
TestFormatSpecArg_BAD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];
    CHAR8  OutBuf[512];

    NetbufCopy(Packet, 0, 255, (UINT8 *)RcvBuf);

    // BAD: RcvBuf is the %s argument — AsciiSPrint scans it for '\0'.
    // If the packet data has no null terminator, this reads out of bounds.
    AsciiSPrint(OutBuf, sizeof(OutBuf), "domain: %s", RcvBuf);

    NetbufFree(Packet);
}

// ---- Test: GOOD - AsciiStrnLenS on tainted buffer ----
// AsciiStrnLenS is a bounded strlen that accepts a MaxSize parameter, so it
// will never scan past the buffer boundary even if the data lacks a null
// terminator.  This is the standard pattern for sizing untrusted input.

VOID
TestAsciiStrnLenS_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];

    NetbufCopy(Packet, 0, sizeof(RcvBuf), (UINT8 *)RcvBuf);

    // GOOD: AsciiStrnLenS is bounded by MaxSize — safe for untrusted data
    UINTN Len = AsciiStrnLenS(RcvBuf, sizeof(RcvBuf));

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: GOOD - Null-termination guard before string use ----
// The function checks that the last byte of the received buffer is zero
// before using it in a string function.  This mirrors Mtftp6ParseStart's
//   if (*((UINT8 *)Packet + PacketLen - 1) != 0) { return; }
// pattern.

VOID
TestStrLen_NullTermGuard_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];
    UINT32 CopyLen;

    CopyLen = NetbufCopy(Packet, 0, sizeof(RcvBuf), (UINT8 *)RcvBuf);

    // Guard: verify the last byte is a null terminator
    if (*((UINT8 *)RcvBuf + CopyLen - 1) != 0) {
        NetbufFree(Packet);
        return;
    }

    // GOOD: null termination verified by guard above
    UINTN Len = AsciiStrLen(RcvBuf);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: GOOD - Positive null-termination guard (== 0) ----
// Same as above but using the positive form: if (last_byte == 0) { use it; }
// instead of the negative form: if (last_byte != 0) { return; }

VOID
TestStrLen_NullTermGuardEq_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    CHAR8  RcvBuf[256];
    UINT32 CopyLen;

    CopyLen = NetbufCopy(Packet, 0, sizeof(RcvBuf), (UINT8 *)RcvBuf);

    // Guard: positive check — last byte IS zero
    if (*((UINT8 *)RcvBuf + CopyLen - 1) == 0) {
        // GOOD: null termination verified by guard
        UINTN Len = AsciiStrLen(RcvBuf);
        (void)Len;
    }

    NetbufFree(Packet);
}

// ---- Test: GOOD - Negative guard with NetbufGetByte (Mtftp6-like pattern) ----
// Uses NetbufGetByte to get a direct pointer into the packet, then checks
// the last byte before treating it as a string.

VOID
TestStrLen_NullTermGuardGetByte_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  *RawData;
    UINT32 PacketLen;

    PacketLen = Packet->TotalSize;
    RawData = NetbufGetByte(Packet, 0, (UINT32 *)0);
    if (RawData == (UINT8 *)0) {
        return;
    }

    // Guard: if last byte is not zero, bail out
    if (*(RawData + PacketLen - 1) != 0) {
        NetbufFree(Packet);
        return;
    }

    // GOOD: null termination verified by guard above
    UINTN Len = AsciiStrLen((CHAR8 *)RawData);

    (void)Len;
    NetbufFree(Packet);
}

// ---- Test: GOOD - Positive guard with NetbufGetByte ----
// Same as above but using the positive == 0 form.

VOID
TestStrLen_NullTermGuardEqGetByte_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    UINT8  *RawData;
    UINT32 PacketLen;

    PacketLen = Packet->TotalSize;
    RawData = NetbufGetByte(Packet, 0, (UINT32 *)0);
    if (RawData == (UINT8 *)0) {
        return;
    }

    // Guard: positive check — last byte IS zero
    if (*(RawData + PacketLen - 1) == 0) {
        // GOOD: null termination verified by guard
        UINTN Len = AsciiStrLen((CHAR8 *)RawData);
        (void)Len;
    }

    NetbufFree(Packet);
}

// ---- Test: GOOD - Interprocedural null-termination guard with output args ----
// A helper validates the last byte before parsing strings and returning them
// through an out-parameter.

VOID
TestStrLen_InterproceduralNullTermGuard_GOOD(
    NET_BUF        *Packet,
    UDP_END_POINT  *EndPoint,
    EFI_STATUS     IoStatus,
    VOID           *Context
    )
{
    OPTION_PACKET_HEADER *ParsedPacket;
    OPTION_PAIR          *Options;
    UINT32               Count;
    UINT32               PacketLen;
    UINTN                Len;
    UINTN                Value;

    PacketLen = Packet->TotalSize;
    ParsedPacket = (OPTION_PACKET_HEADER *)NetbufGetByte(Packet, 0, (UINT32 *)0);
    if (ParsedPacket == (OPTION_PACKET_HEADER *)0) {
        return;
    }

    Count = 0;
    Options = (OPTION_PAIR *)0;

    if (ParseDelimitedStart(ParsedPacket, PacketLen, &Count, &Options) != EFI_SUCCESS) {
        NetbufFree(Packet);
        return;
    }

    if ((Options != (OPTION_PAIR *)0) && (Count > 0)) {
        Len = AsciiStrLen(Options[0].OptionStr);
        Value = AsciiStrDecimalToUintn(Options[0].ValueStr);
        (void)Len;
        (void)Value;
    }

    FreePool(Options);
    NetbufFree(Packet);
}
