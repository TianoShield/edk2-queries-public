#ifndef TEST_INCLUDE_PXEBCDHCP6_C
#define TEST_INCLUDE_PXEBCDHCP6_C

//
// Simplified copy of NetworkPkg/UefiPxeBcDxe/PxeBcDhcp6.c support needed to
// exercise CVE-2023-45235: PxeBcDhcp6SeekOption returns a pointer *into* the
// attacker-controlled DHCPv6 offer option bytes it is handed.
//

// SwapBytes16 is modeled as a value-preserving taint function; NTOHS/HTONS in
// NetworkPkg expand to it.
UINT16 SwapBytes16 (UINT16 Value);
UINT16 ReadUnaligned16 (UINT16 *Buffer);

#define NTOHS(x)  SwapBytes16 (x)
#define HTONS(x)  SwapBytes16 (x)

#define PXEBC_COMBINED_SIZE_OF_OPT_CODE_AND_LEN  (sizeof (UINT16) + sizeof (UINT16))
#define PXEBC_MIN_SIZE_OF_DUID                   (sizeof (UINT16) + 1)
#define PXEBC_MAX_SIZE_OF_DUID                   (sizeof (UINT16) + 128)
#define DHCP6_OPT_SERVER_ID                      2

UINT8 *
PxeBcDhcp6SeekOption (
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

#endif
