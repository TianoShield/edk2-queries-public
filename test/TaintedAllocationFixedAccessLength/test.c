/**
 * Test cases for TaintedAllocationFixedWrite query.
 *
 * Models the EDK2 PXE Base Code DHCPv6 path of CVE-2023-45234
 * (NetworkPkg/UefiPxeBcDxe/PxeBcDhcp6.c, PxeBcCacheDnsServerAddresses): an
 * attacker-controlled DNS-server option length (`OptList[..]->OpLen`) sizes a
 * pool allocation, which is then written with a *fixed* `sizeof
 * (EFI_IPv6_ADDRESS)` (16-byte) CopyMem. When the option length is < 16 the
 * destination is under-allocated and the fixed copy overflows it.
 *
 * BAD functions under-allocate (attacker size, fixed copy) and must alert.
 * GOOD functions either allocate a constant size (the upstream fix) or bound
 * the attacker size below before allocating, and must not alert.
 */

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long   UINTN;
typedef void            VOID;
typedef UINTN           EFI_STATUS;

#define NULL                  ((VOID *)0)
#define EFI_SUCCESS           0
#define EFI_DEVICE_ERROR      7
#define EFI_OUT_OF_RESOURCES  9

// ---- BaseMemoryLib / MemoryAllocationLib / BaseLib stubs ----
VOID *AllocatePool (UINTN AllocationSize);
VOID *AllocateZeroPool (UINTN AllocationSize);
VOID *CopyMem (VOID *Destination, VOID *Source, UINTN Length);
VOID *SetMem (VOID *Buffer, UINTN Length, UINT8 Value);

// SwapBytes16 is modeled as a value-preserving taint function; NTOHS expands to it.
UINT16 SwapBytes16 (UINT16 Value);
#define NTOHS(x)  SwapBytes16 (x)

typedef struct {
  UINT8  Addr[16];
} EFI_IPv6_ADDRESS;

#pragma pack(1)
typedef struct {
  UINT16  OpCode;
  UINT16  OpLen;
  UINT8   Data[1];
} EFI_DHCP6_PACKET_OPTION;
#pragma pack()

#define PXEBC_DHCP6_IDX_DNS_SERVER  5
#define PXEBC_DHCP6_IDX_MAX         7

// PXEBC_DHCP6_PACKET_CACHE.OptList[] entries point *into* the cached attacker
// offer packet, so reads through them are attacker-controlled.
typedef struct {
  EFI_DHCP6_PACKET_OPTION  *OptList[PXEBC_DHCP6_IDX_MAX];
} PXEBC_DHCP6_PACKET_CACHE;

typedef struct _PXEBC_PRIVATE_DATA {
  EFI_IPv6_ADDRESS  *DnsServer;
} PXEBC_PRIVATE_DATA;

// ---- BAD: attacker-controlled allocation size, fixed-size copy ----

// Faithful CVE-2023-45234: alloc OpLen bytes, CopyMem a fixed 16 bytes.
EFI_STATUS
PxeBcCacheDnsServerAddresses_BAD (PXEBC_PRIVATE_DATA *Private, PXEBC_DHCP6_PACKET_CACHE *Cache6)
{
  Private->DnsServer =
    AllocateZeroPool (NTOHS (Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->OpLen));
  if (Private->DnsServer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (
    Private->DnsServer,
    Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->Data,
    sizeof (EFI_IPv6_ADDRESS)
    );                                                            // $Alert
  return EFI_SUCCESS;
}

// Variant: allocation parked in a local variable, attacker length via an
// intermediate option pointer.
EFI_STATUS
PxeBcCacheDns_BAD_LocalCursor (PXEBC_DHCP6_PACKET_CACHE *Cache6)
{
  EFI_DHCP6_PACKET_OPTION  *Opt = Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER];
  UINT8                    *Buf = AllocateZeroPool (NTOHS (Opt->OpLen));

  if (Buf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (Buf, Opt->Data, sizeof (EFI_IPv6_ADDRESS));           // $Alert
  return EFI_SUCCESS;
}

// Variant: AllocatePool + a fixed-size SetMem write.
EFI_STATUS
PxeBcCacheDns_BAD_SetMem (PXEBC_DHCP6_PACKET_CACHE *Cache6)
{
  UINT8  *Buf = AllocatePool (NTOHS (Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->OpLen));

  if (Buf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  SetMem (Buf, sizeof (EFI_IPv6_ADDRESS), 0);                    // $Alert
  return EFI_SUCCESS;
}

// ---- GOOD: not under-allocatable ----

// The upstream fix: allocate a constant size (>= the fixed copy), so the
// allocation size carries no attacker taint.
EFI_STATUS
PxeBcCacheDns_GOOD_ConstAlloc (PXEBC_PRIVATE_DATA *Private, PXEBC_DHCP6_PACKET_CACHE *Cache6)
{
  Private->DnsServer = AllocateZeroPool (sizeof (EFI_IPv6_ADDRESS));
  if (Private->DnsServer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (
    Private->DnsServer,
    Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->Data,
    sizeof (EFI_IPv6_ADDRESS)
    );                                                            // Safe
  return EFI_SUCCESS;
}

// Bound the attacker length below before allocating it.
EFI_STATUS
PxeBcCacheDns_GOOD_LenCheck (PXEBC_PRIVATE_DATA *Private, PXEBC_DHCP6_PACKET_CACHE *Cache6)
{
  UINT16  DnsServerLen = NTOHS (Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->OpLen);

  if (DnsServerLen < sizeof (EFI_IPv6_ADDRESS)) {
    return EFI_DEVICE_ERROR;
  }

  Private->DnsServer = AllocateZeroPool (DnsServerLen);
  if (Private->DnsServer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (
    Private->DnsServer,
    Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->Data,
    sizeof (EFI_IPv6_ADDRESS)
    );                                                            // Safe
  return EFI_SUCCESS;
}
