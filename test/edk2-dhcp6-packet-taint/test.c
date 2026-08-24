#include "../include/NetBuffer.c"

typedef struct {
  UINT32    MessageType   : 8;
  UINT32    TransactionId : 24;
} EFI_DHCP6_HEADER;

typedef struct {
  UINT32    Size;
  UINT32    Length;
  struct {
    EFI_DHCP6_HEADER    Header;
    UINT8               Option[1];
  } Dhcp6;
} EFI_DHCP6_PACKET;

//
// Mirrors NetworkPkg Dhcp6Dxe `Dhcp6ReceivePacket`: a received NET_BUF is
// flattened into a freshly allocated EFI_DHCP6_PACKET via NetbufCopy writing
// through the address of the embedded header, after which the driver parses the
// option area. Verifies that `netbufCopyDestObjectStep` plus the
// EFI_DHCP6_PACKET TaintInheritingContent models recover taint into
// `Packet->Dhcp6.Option` across the `&Packet->Dhcp6.Header` destination alias.
//
UINT8 *
ProbeDhcp6PacketTaint (
  IN NET_BUF  *Udp6Wrap
  )
{
  EFI_DHCP6_PACKET  *Packet;
  EFI_DHCP6_HEADER  *Head;

  Packet         = (EFI_DHCP6_PACKET *)AllocatePool (sizeof (EFI_DHCP6_PACKET) + 256);
  Head           = &Packet->Dhcp6.Header;
  Packet->Length = NetbufCopy (Udp6Wrap, 0, 256, (UINT8 *)Head);

  return Packet->Dhcp6.Option;
}
