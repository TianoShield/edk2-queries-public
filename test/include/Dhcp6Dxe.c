#ifndef TEST_INCLUDE_DHCP6DXE_C
#define TEST_INCLUDE_DHCP6DXE_C

//
// Simplified copy of NetworkPkg/Dhcp6Dxe support needed to exercise
// CVE-2023-45230. Dhcp6SeekOption returns a pointer *into* the attacker-
// controlled option area it is handed. Two versions of the option appender are
// provided: the reverted (vulnerable) Dhcp6AppendOption copies OptLen bytes into
// a raw buffer cursor with no packet buffer-space check, while the fixed
// Dhcp6AppendOptionChecked adds the CVE-2023-45230 `Length < BytesNeeded` guard.
// EFI_DHCP6_PACKET / EFI_DHCP6_HEADER / EFI_DHCP6_PACKET_OPTION and the
// SwapBytes16/NTOHS models come from the includes already pulled into test.c
// (PxeBcDhcp6.c).
//

#define DHCP6_BASE_PACKET_SIZE  1024
#define DHCP6_OPT_SERVER_ID     2

void *AllocateZeroPool (UINTN Size);

// EFI_DHCP6_DUID: the DUID carried in a Server ID / Client ID option. Length is
// attacker-controlled (network byte order) when the DUID is read out of a
// received packet.
typedef struct {
  UINT16  Length;
  UINT8   Duid[1];
} EFI_DHCP6_DUID;

// Dhcp6SeekOption walks the option area Buf and returns a pointer into it; the
// running cursor arithmetic hides the flow from the IR, so lib models it as
// arg[*0] -> return[*].
UINT8 *
Dhcp6SeekOption (
  UINT8   *Buf,
  UINT32  SeekLen,
  UINT16  OptType
  )
{
  UINT8   *Cursor;
  UINT8   *Option;
  UINT16  DataLen;
  UINT16  OpCode;

  Option = (UINT8 *)0;
  Cursor = Buf;

  while (Cursor < Buf + SeekLen) {
    OpCode = ReadUnaligned16 ((UINT16 *)Cursor);
    if (OpCode == HTONS (OptType)) {
      Option = Cursor;
      break;
    }

    DataLen = NTOHS (ReadUnaligned16 ((UINT16 *)(Cursor + 2)));
    Cursor += (DataLen + 4);
  }

  return Option;
}

VOID WriteUnaligned16 (UINT16 *Buffer, UINT16 Value);

// Reverted (vulnerable) Dhcp6AppendOption: copies NTOHS(OptLen) bytes into the
// raw cursor Buf with no buffer-space check, then advances Buf. The CopyMem
// here is the CVE-2023-45230 sink; Buf points into the caller's fixed
// AllocateZeroPool(DHCP6_BASE_PACKET_SIZE + UserLen) packet.
UINT8 *
Dhcp6AppendOption (
  UINT8   *Buf,
  UINT16  OptType,
  UINT16  OptLen,
  UINT8   *Data
  )
{
  WriteUnaligned16 ((UINT16 *)Buf, OptType);
  Buf += 2;
  WriteUnaligned16 ((UINT16 *)Buf, OptLen);
  Buf += 2;
  CopyMem (Buf, Data, NTOHS (OptLen));  // sink
  Buf += NTOHS (OptLen);

  return Buf;
}

#define DHCP6_SIZE_OF_COMBINED_CODE_AND_LEN  (sizeof (UINT16) + sizeof (UINT16))

// The patched Dhcp6AppendOption computes BytesNeeded = 4 + NTOHS(OptLen) and
// rejects the copy when the space remaining in the packet
// (Packet->Size - Packet->Length) is smaller. The dominating
// `Length < BytesNeeded` check is what isUpperBoundGuarded matches (resolving
// the BytesNeeded local to its definition via GVN), so this CopyMem is not
// reported. This is the CVE-2023-45230 fix.
UINT8 *
Dhcp6AppendOptionChecked (
  EFI_DHCP6_PACKET  *Packet,
  UINT8             *Buf,
  UINT16            OptType,
  UINT16            OptLen,
  UINT8             *Data
  )
{
  UINT32  Length;
  UINT32  BytesNeeded;

  BytesNeeded = DHCP6_SIZE_OF_COMBINED_CODE_AND_LEN + NTOHS (OptLen);
  Length      = Packet->Size - Packet->Length;
  if (Length < BytesNeeded) {
    return (UINT8 *)0;  // EFI_BUFFER_TOO_SMALL
  }

  WriteUnaligned16 ((UINT16 *)Buf, OptType);
  Buf += 2;
  WriteUnaligned16 ((UINT16 *)Buf, OptLen);
  Buf += 2;
  CopyMem (Buf, Data, NTOHS (OptLen));  // guarded — barrier suppresses
  Buf += NTOHS (OptLen);

  return Buf;
}

#endif
