/** Tests published DHCPv6 CVE patterns and their upper-bound guards. */

#include "../include/NetBuffer.c"

// ============================================================================
// CVE-2023-45235 — PXE Base Code DHCPv6 Server ID option buffer overflow.
//
// PxeBcRequestBootService copies a DHCPv6 option out of a cached (attacker-
// controlled) proxy offer into a fixed-size Discover buffer, using the option's
// own OpLen field as the CopyMem length. Without a bounds check on OpLen the
// copy overflows the Discover buffer.
// ============================================================================

#include "../include/PxeBcDhcp6.c"

typedef struct {
    UINT32  TransactionId;
    UINT8   MessageType;
} EFI_DHCP6_HEADER;

#pragma pack(1)
typedef struct {
    UINT16  OpCode;
    UINT16  OpLen;
    UINT8   Data[1];
} EFI_DHCP6_PACKET_OPTION;
#pragma pack()

typedef struct {
    UINT32  Size;
    UINT32  Length;
    struct {
        EFI_DHCP6_HEADER  Header;
        UINT8             Option[1];
    } Dhcp6;
} EFI_DHCP6_PACKET;

// PXE BC private data caches each received DHCPv6 packet in this union
// (PxeBcDhcp6.h), and copies the sent Request into Dhcp6Request. The query
// sources the OfferBuffer[]/Dhcp6Request reads at the top of the vulnerable
// functions.
typedef union {
    EFI_DHCP6_PACKET  Offer;
    EFI_DHCP6_PACKET  Ack;
    UINT8             Buffer[2048];
} PXEBC_DHCP6_PACKET;

typedef struct {
    PXEBC_DHCP6_PACKET  Packet;
} PXEBC_DHCP6_PACKET_CACHE;

typedef union {
    PXEBC_DHCP6_PACKET_CACHE  Dhcp6;
} PXEBC_DHCP_PACKET_CACHE;

#define PXEBC_OFFER_MAX_NUM 16
typedef struct _PXEBC_PRIVATE_DATA {
    PXEBC_DHCP_PACKET_CACHE  OfferBuffer[PXEBC_OFFER_MAX_NUM];  // received offers (source)
    EFI_DHCP6_PACKET         *Dhcp6Request;                     // copied sent Request (source)
} PXEBC_PRIVATE_DATA;

// Fixed-size Discover buffer (EFI_PXE_BASE_CODE_DHCPV6_PACKET in EDK2). The
// option bytes live in the fixed-capacity DhcpOptions[1024] array field, which
// is what the CopyMem destination (DiscoverOpt) points into — exactly the array
// CVE-2023-45235 overflows.
typedef struct {
    UINT32  MessageType   : 8;
    UINT32  TransactionId : 24;
    UINT8   DhcpOptions[1024];
} EFI_PXE_BASE_CODE_DHCPV6_PACKET;

// ---- Test: BAD - unguarded Server ID OpLen as CopyMem length (CVE-2023-45235) ----

EFI_STATUS
PxeBcRequestBootService_BAD(PXEBC_PRIVATE_DATA *Private, UINTN Index,
                            EFI_PXE_BASE_CODE_DHCPV6_PACKET *Discover)
{
    EFI_DHCP6_PACKET  *IndexOffer;
    UINT8             *Option;
    UINT8             *DiscoverOpt;
    UINT16            OpLen;

    DiscoverOpt = Discover->DhcpOptions;
    IndexOffer  = &Private->OfferBuffer[Index].Dhcp6.Packet.Offer;  // source: cached offer

    Option = PxeBcDhcp6SeekOption(IndexOffer->Dhcp6.Option,
                                  IndexOffer->Length - 4,
                                  DHCP6_OPT_SERVER_ID);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    OpLen = NTOHS(((EFI_DHCP6_PACKET_OPTION *)Option)->OpLen);

    // BAD: OpLen is attacker-controlled and unchecked → OOB write.
    CopyMem(DiscoverOpt, Option, OpLen + PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN);  // $Alert

    return 0;
}

// ---- Test: BAD - unguarded option-loop copy from the request (CVE-2023-45235) ----
// The CVE fix also bounds the Private->Dhcp6Request->Dhcp6.Option copies
// (PxeBcDhcp6.c:954, :2218); the request packet echoes server-supplied options,
// so its option lengths are attacker-influenced too.

EFI_STATUS
PxeBcCopyRequestOption_BAD(PXEBC_PRIVATE_DATA *Private, EFI_PXE_BASE_CODE_DHCPV6_PACKET *Discover)
{
    EFI_DHCP6_PACKET  *Request;
    UINT8             *RequestOpt;
    UINT8             *DiscoverOpt;
    UINT16            OpLen;

    DiscoverOpt = Discover->DhcpOptions;
    Request     = Private->Dhcp6Request;     // source: cached sent-request packet
    RequestOpt  = Request->Dhcp6.Option;

    OpLen = NTOHS(((EFI_DHCP6_PACKET_OPTION *)RequestOpt)->OpLen);

    // BAD: OpLen is attacker-influenced and unchecked → OOB write.
    CopyMem(DiscoverOpt, RequestOpt, OpLen + PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN);  // $Alert

    return 0;
}

// ---- Test: GOOD - DUID min/max check bounds OpLen (atomic guard) ----

EFI_STATUS
PxeBcRequestBootService_GOOD_DuidCheck(PXEBC_PRIVATE_DATA *Private, UINTN Index,
                                       EFI_PXE_BASE_CODE_DHCPV6_PACKET *Discover)
{
    EFI_DHCP6_PACKET  *IndexOffer;
    UINT8             *Option;
    UINT8             *DiscoverOpt;
    UINT16            OpLen;

    DiscoverOpt = Discover->DhcpOptions;
    IndexOffer  = &Private->OfferBuffer[Index].Dhcp6.Packet.Offer;

    Option = PxeBcDhcp6SeekOption(IndexOffer->Dhcp6.Option, IndexOffer->Length - 4,
                                  DHCP6_OPT_SERVER_ID);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    OpLen = NTOHS(((EFI_DHCP6_PACKET_OPTION *)Option)->OpLen);

    // GOOD: the CVE-2023-45235 fix bounds OpLen directly before the copy.
    if ((OpLen < PXEBC_MIN_SIZE_OF_DUID) || (OpLen > PXEBC_MAX_SIZE_OF_DUID)) {
        return 2;
    }

    CopyMem(DiscoverOpt, Option, OpLen + PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN);  // Safe

    return 0;
}

// ---- Test: GOOD - total-length check bounds the copy (composite guard) ----

EFI_STATUS
PxeBcRequestBootService_GOOD_LenCheck(PXEBC_PRIVATE_DATA *Private, UINTN Index,
                                      EFI_PXE_BASE_CODE_DHCPV6_PACKET *Discover)
{
    EFI_DHCP6_PACKET  *IndexOffer;
    UINT8             *Option;
    UINT8             *DiscoverOpt;
    UINT16            OpLen;
    UINTN             DiscoverLen      = sizeof(EFI_DHCP6_HEADER);
    UINTN             DiscoverLenNeeded = sizeof(EFI_PXE_BASE_CODE_DHCPV6_PACKET);

    DiscoverOpt = Discover->DhcpOptions;
    IndexOffer  = &Private->OfferBuffer[Index].Dhcp6.Packet.Offer;

    Option = PxeBcDhcp6SeekOption(IndexOffer->Dhcp6.Option, IndexOffer->Length - 4,
                                  DHCP6_OPT_SERVER_ID);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    OpLen = NTOHS(((EFI_DHCP6_PACKET_OPTION *)Option)->OpLen);

    // GOOD: the CVE-2023-45235 fix bounds the running total against the buffer.
    if ((DiscoverLen + OpLen + PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN) > DiscoverLenNeeded) {
        return 3;
    }

    CopyMem(DiscoverOpt, Option, OpLen + PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN);  // Safe

    return 0;
}

// ============================================================================
// CVE-2023-45230 — NetworkPkg/Dhcp6Dxe outgoing-packet buffer overflow.
//
// The DHCP6 client caches each received Advertise/Reply. When it assembles an
// outgoing message it seeks the Server ID option out of that cached packet,
// reads the option's DUID Length, and passes it to Dhcp6AppendOption, whose
// CopyMem(Buf, Data, NTOHS(OptLen)) copies the DUID into a fixed 1024-byte
// AllocateZeroPool packet. The DUID length is attacker-controlled and unrelated
// to the packet size, so an oversized Server ID overflows the packet.
//   - Request  reads Instance->AdSelect        (_DHCP6_INSTANCE.AdSelect source)
//   - Decline/Release/Renew read Ia->ReplyPacket (EFI_DHCP6_IA.ReplyPacket source)
// The fix bounds the copy against the remaining packet space before CopyMem.
// ============================================================================

#include "../include/Dhcp6Dxe.c"

// EFI_DHCP6_IA (MdePkg/Protocol/Dhcp6.h) caches the latest Reply in ReplyPacket;
// the Decline/Release/RenewRebind assembly functions read it as their source.
typedef struct {
    UINT32            IaId;
    EFI_DHCP6_PACKET  *ReplyPacket;
} EFI_DHCP6_IA;

typedef struct {
    EFI_DHCP6_IA  *Ia;
} DHCP6_IA_CB;

// _DHCP6_INSTANCE (Dhcp6Impl.h) caches the selected Advertise in AdSelect; the
// Request assembly function reads it as its source.
typedef struct _DHCP6_INSTANCE {
    EFI_DHCP6_PACKET  *AdSelect;
    DHCP6_IA_CB        IaCb;
} DHCP6_INSTANCE;

#define Dhcp6OptServerId  2

// ---- Test: BAD - Server ID DUID length from cached Advertise (AdSelect) ----

EFI_STATUS
Dhcp6SendRequestMsg_BAD(DHCP6_INSTANCE *Instance)
{
    EFI_DHCP6_PACKET  *Packet;
    EFI_DHCP6_DUID    *ServerId;
    UINT8             *Option;
    UINT8             *Cursor;

    // source: the cached selected Advertise packet.
    Option = Dhcp6SeekOption(Instance->AdSelect->Dhcp6.Option,
                             Instance->AdSelect->Length - sizeof(EFI_DHCP6_HEADER),
                             Dhcp6OptServerId);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    ServerId = (EFI_DHCP6_DUID *)(Option + 2);

    Packet = (EFI_DHCP6_PACKET *)AllocateZeroPool(DHCP6_BASE_PACKET_SIZE);
    if (Packet == (EFI_DHCP6_PACKET *)0) {
        return 2;
    }
    Cursor = Packet->Dhcp6.Option;

    // BAD: ServerId->Length is attacker-controlled and unchecked; the CopyMem
    // inside Dhcp6AppendOption overflows the fixed 1024-byte packet.
    Cursor = Dhcp6AppendOption(Cursor, HTONS(Dhcp6OptServerId),
                               ServerId->Length, ServerId->Duid);  // $Alert (sink in fixture)

    return 0;
}

// ---- Test: BAD - Server ID DUID length from cached Reply (Ia->ReplyPacket) ----

EFI_STATUS
Dhcp6SendDeclineMsg_BAD(DHCP6_INSTANCE *Instance)
{
    EFI_DHCP6_PACKET  *ReplyPacket;
    EFI_DHCP6_PACKET  *Packet;
    EFI_DHCP6_DUID    *ServerId;
    UINT8             *Option;
    UINT8             *Cursor;

    ReplyPacket = Instance->IaCb.Ia->ReplyPacket;  // source: the cached Reply packet

    Option = Dhcp6SeekOption(ReplyPacket->Dhcp6.Option,
                             ReplyPacket->Length - sizeof(EFI_DHCP6_HEADER),
                             Dhcp6OptServerId);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    ServerId = (EFI_DHCP6_DUID *)(Option + 2);

    Packet = (EFI_DHCP6_PACKET *)AllocateZeroPool(DHCP6_BASE_PACKET_SIZE);
    if (Packet == (EFI_DHCP6_PACKET *)0) {
        return 2;
    }
    Cursor = Packet->Dhcp6.Option;

    // BAD: same overflow via the cached Reply's Server ID DUID length.
    Cursor = Dhcp6AppendOption(Cursor, HTONS(Dhcp6OptServerId),
                               ServerId->Length, ServerId->Duid);  // $Alert (sink in fixture)

    return 0;
}

// ---- Test: GOOD - patched appender bounds the copy against packet space ----

EFI_STATUS
Dhcp6SendRequestMsg_GOOD(DHCP6_INSTANCE *Instance)
{
    EFI_DHCP6_PACKET  *Packet;
    EFI_DHCP6_DUID    *ServerId;
    UINT8             *Option;
    UINT8             *Cursor;

    Option = Dhcp6SeekOption(Instance->AdSelect->Dhcp6.Option,
                             Instance->AdSelect->Length - sizeof(EFI_DHCP6_HEADER),
                             Dhcp6OptServerId);
    if (Option == (UINT8 *)0) {
        return 1;
    }

    ServerId = (EFI_DHCP6_DUID *)(Option + 2);

    Packet = (EFI_DHCP6_PACKET *)AllocateZeroPool(DHCP6_BASE_PACKET_SIZE);
    if (Packet == (EFI_DHCP6_PACKET *)0) {
        return 2;
    }
    Packet->Size   = DHCP6_BASE_PACKET_SIZE;
    Packet->Length = sizeof(EFI_DHCP6_HEADER);
    Cursor = Packet->Dhcp6.Option;

    // GOOD: the CVE-2023-45230 fix checks the remaining packet space against
    // BytesNeeded (= 4 + NTOHS(OptLen)) before the CopyMem, so the upper-bound
    // guard barrier suppresses the now-bounded copy.
    Cursor = Dhcp6AppendOptionChecked(Packet, Cursor, HTONS(Dhcp6OptServerId),
                                      ServerId->Length, ServerId->Duid);  // Safe

    return 0;
}
