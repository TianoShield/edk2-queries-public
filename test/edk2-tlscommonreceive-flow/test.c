#include "../include/HttpsSupport.c"

EFI_STATUS
EFIAPI
FakeTcp4Receive (
  IN EFI_TCP4_PROTOCOL  *This,
  IN EFI_TCP4_IO_TOKEN  *Token
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FakeTcp6Receive (
  IN EFI_TCP6_PROTOCOL  *This,
  IN EFI_TCP6_IO_TOKEN  *Token
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FakeGetSessionData (
  IN EFI_TLS_PROTOCOL          *This,
  IN EFI_TLS_SESSION_DATA_TYPE DataType,
  OUT VOID                     *Data,
  IN OUT UINTN                 *DataSize
  )
{
  if (*DataSize < sizeof(EFI_TLS_SESSION_STATE)) {
    *DataSize = sizeof(EFI_TLS_SESSION_STATE);
    return EFI_BUFFER_TOO_SMALL;
  }

  *(EFI_TLS_SESSION_STATE *)Data = EfiTlsSessionDataTransferring;
  *DataSize = sizeof(EFI_TLS_SESSION_STATE);
  return EFI_SUCCESS;
}

static
VOID
InitTcp4HttpInstance (
  HTTP_PROTOCOL         *Http,
  EFI_TCP4_PROTOCOL     *Tcp4,
  EFI_TCP4_RECEIVE_DATA *RxData,
  EFI_TLS_PROTOCOL      *Tls
  )
{
  Http->LocalAddressIsIPv6           = FALSE;
  Http->Tcp4                         = Tcp4;
  Http->Tcp6                         = (EFI_TCP6_PROTOCOL *)0;
  Http->Tcp4TlsRxToken.Packet.RxData = RxData;
  Http->Tls                          = Tls;
}

static
VOID
InitTcp6HttpInstance (
  HTTP_PROTOCOL         *Http,
  EFI_TCP6_PROTOCOL     *Tcp6,
  EFI_TCP6_RECEIVE_DATA *RxData,
  EFI_TLS_PROTOCOL      *Tls
  )
{
  Http->LocalAddressIsIPv6           = TRUE;
  Http->Tcp4                         = (EFI_TCP4_PROTOCOL *)0;
  Http->Tcp6                         = Tcp6;
  Http->Tcp6TlsRxToken.Packet.RxData = RxData;
  Http->Tls                          = Tls;
}

UINT8 *
ProbeTlsCommonReceiveGetByteTcp4OneBlock (
  VOID
  )
{
  EFI_TCP4_PROTOCOL      Tcp4 = { FakeTcp4Receive };
  EFI_TCP4_RECEIVE_DATA  Rx4Data;
  HTTP_PROTOCOL          Http;
  UINT8                  Block0[8];
  NET_BUF                *Packet;

  Packet = MakeSingleBlockPacket(Block0, sizeof(Block0));
  InitTcp4HttpInstance(&Http, &Tcp4, &Rx4Data, (EFI_TLS_PROTOCOL *)0);
  TlsCommonReceive(&Http, Packet, NULL);
  return NetbufGetByte(Packet, 0, (UINT32 *)0);
}

UINT8 *
ProbeTlsCommonReceiveGetByteTcp6TwoBlock (
  VOID
  )
{
  EFI_TCP6_PROTOCOL      Tcp6 = { FakeTcp6Receive };
  EFI_TCP6_RECEIVE_DATA  Rx6Data;
  HTTP_PROTOCOL          Http;
  UINT8                  Block0[4];
  UINT8                  Block1[4];
  NET_BUF                *Packet;

  Packet = MakeTwoBlockPacket(Block0, sizeof(Block0), Block1, sizeof(Block1));
  InitTcp6HttpInstance(&Http, &Tcp6, &Rx6Data, (EFI_TLS_PROTOCOL *)0);
  TlsCommonReceive(&Http, Packet, NULL);
  return NetbufGetByte(Packet, 0, (UINT32 *)0);
}

VOID
ProbeTlsCommonReceiveCopyTcp4TwoBlock (
  UINT8  *Dest
  )
{
  EFI_TCP4_PROTOCOL      Tcp4 = { FakeTcp4Receive };
  EFI_TCP4_RECEIVE_DATA  Rx4Data;
  HTTP_PROTOCOL          Http;
  UINT8                  Block0[4];
  UINT8                  Block1[4];
  NET_BUF                *Packet;

  Packet = MakeTwoBlockPacket(Block0, sizeof(Block0), Block1, sizeof(Block1));
  InitTcp4HttpInstance(&Http, &Tcp4, &Rx4Data, (EFI_TLS_PROTOCOL *)0);
  TlsCommonReceive(&Http, Packet, NULL);
  NetbufCopy(Packet, 0, 8, Dest);
}

VOID
ProbeTlsCommonReceiveCopyTcp6OneBlock (
  UINT8  *Dest
  )
{
  EFI_TCP6_PROTOCOL      Tcp6 = { FakeTcp6Receive };
  EFI_TCP6_RECEIVE_DATA  Rx6Data;
  HTTP_PROTOCOL          Http;
  UINT8                  Block0[8];
  NET_BUF                *Packet;

  Packet = MakeSingleBlockPacket(Block0, sizeof(Block0));
  InitTcp6HttpInstance(&Http, &Tcp6, &Rx6Data, (EFI_TLS_PROTOCOL *)0);
  TlsCommonReceive(&Http, Packet, NULL);
  NetbufCopy(Packet, 0, 8, Dest);
}

VOID
ProbeTlsReceiveOnePduCopyTcp4 (
  UINT8  *Dest
  )
{
  EFI_TCP4_PROTOCOL      Tcp4 = { FakeTcp4Receive };
  EFI_TCP4_RECEIVE_DATA  Rx4Data;
  EFI_TLS_PROTOCOL       Tls = { 0, FakeGetSessionData, TlsBuildResponsePacket, 0 };
  HTTP_PROTOCOL          Http;
  NET_BUF                *Pdu;

  InitTcp4HttpInstance(&Http, &Tcp4, &Rx4Data, &Tls);
  TlsReceiveOnePdu(&Http, &Pdu, NULL);
  NetbufCopy(Pdu, 0, Pdu->TotalSize, Dest);
}

VOID
ProbeTlsReceiveOnePduCopyTcp6 (
  UINT8  *Dest
  )
{
  EFI_TCP6_PROTOCOL      Tcp6 = { FakeTcp6Receive };
  EFI_TCP6_RECEIVE_DATA  Rx6Data;
  EFI_TLS_PROTOCOL       Tls = { 0, FakeGetSessionData, TlsBuildResponsePacket, 0 };
  HTTP_PROTOCOL          Http;
  NET_BUF                *Pdu;

  InitTcp6HttpInstance(&Http, &Tcp6, &Rx6Data, &Tls);
  TlsReceiveOnePdu(&Http, &Pdu, NULL);
  NetbufCopy(Pdu, 0, Pdu->TotalSize, Dest);
}

VOID
ProbeHttpsReceiveTcp4 (
  UINT8  *Dest
  )
{
  EFI_TCP4_PROTOCOL      Tcp4 = { FakeTcp4Receive };
  EFI_TCP4_RECEIVE_DATA  Rx4Data;
  EFI_TLS_PROTOCOL       Tls = { 0, FakeGetSessionData, TlsBuildResponsePacket, 0 };
  HTTP_PROTOCOL          Http;
  NET_FRAGMENT           Fragment;

  InitTcp4HttpInstance(&Http, &Tcp4, &Rx4Data, &Tls);
  HttpsReceive(&Http, &Fragment, NULL);
  CopyMem(Dest, Fragment.Bulk, Fragment.Len);
}

VOID
ProbeHttpsReceiveTcp6 (
  UINT8  *Dest
  )
{
  EFI_TCP6_PROTOCOL      Tcp6 = { FakeTcp6Receive };
  EFI_TCP6_RECEIVE_DATA  Rx6Data;
  EFI_TLS_PROTOCOL       Tls = { 0, FakeGetSessionData, TlsBuildResponsePacket, 0 };
  HTTP_PROTOCOL          Http;
  NET_FRAGMENT           Fragment;

  InitTcp6HttpInstance(&Http, &Tcp6, &Rx6Data, &Tls);
  HttpsReceive(&Http, &Fragment, NULL);
  CopyMem(Dest, Fragment.Bulk, Fragment.Len);
}
