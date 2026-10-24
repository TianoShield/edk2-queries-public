#ifndef TEST_INCLUDE_HTTPSSUPPORT_C
#define TEST_INCLUDE_HTTPSSUPPORT_C

#include "NetBuffer.c"
#include "TlsProtocol.c"

#define DEF_BUF_LEN 64

typedef enum {
  TlsContentTypeChangeCipherSpec = 20,
  TlsContentTypeAlert            = 21,
  TlsContentTypeHandshake        = 22,
  TlsContentTypeApplicationData  = 23
} TLS_CONTENT_TYPE;

typedef struct {
  UINT8            ContentType;
  EFI_TLS_VERSION  Version;
  UINT16           Length;
} TLS_RECORD_HEADER;

#define TLS_RECORD_HEADER_LENGTH      5
#define TLS10_PROTOCOL_VERSION_MINOR  1
#define TLS11_PROTOCOL_VERSION_MINOR  2
#define TLS12_PROTOCOL_VERSION_MINOR  3

typedef struct {
  EFI_STATUS  Status;
  EFI_EVENT   Event;
} EFI_TCP_COMPLETION_TOKEN;

typedef struct {
  UINT32  FragmentLength;
  VOID    *FragmentBuffer;
} EFI_TCP4_FRAGMENT_DATA;

typedef struct {
  UINT32  FragmentLength;
  VOID    *FragmentBuffer;
} EFI_TCP6_FRAGMENT_DATA;

typedef struct {
  UINT32                  DataLength;
  UINT32                  FragmentCount;
  EFI_TCP4_FRAGMENT_DATA  FragmentTable[1];
} EFI_TCP4_RECEIVE_DATA;

typedef struct {
  UINT32                  DataLength;
  UINT32                  FragmentCount;
  EFI_TCP6_FRAGMENT_DATA  FragmentTable[1];
} EFI_TCP6_RECEIVE_DATA;

typedef union {
  EFI_TCP4_RECEIVE_DATA  *RxData;
} EFI_TCP4_PACKET;

typedef union {
  EFI_TCP6_RECEIVE_DATA  *RxData;
} EFI_TCP6_PACKET;

typedef struct {
  EFI_TCP_COMPLETION_TOKEN  CompletionToken;
  EFI_TCP4_PACKET           Packet;
} EFI_TCP4_IO_TOKEN;

typedef struct {
  EFI_TCP_COMPLETION_TOKEN  CompletionToken;
  EFI_TCP6_PACKET           Packet;
} EFI_TCP6_IO_TOKEN;

typedef struct EFI_TCP4_PROTOCOL EFI_TCP4_PROTOCOL;
typedef struct EFI_TCP6_PROTOCOL EFI_TCP6_PROTOCOL;
typedef struct _HTTP_PROTOCOL HTTP_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_TCP4_RECEIVE_FN) (
  IN EFI_TCP4_PROTOCOL  *This,
  IN EFI_TCP4_IO_TOKEN  *Token
  );

typedef
EFI_STATUS
(EFIAPI *EFI_TCP6_RECEIVE_FN) (
  IN EFI_TCP6_PROTOCOL  *This,
  IN EFI_TCP6_IO_TOKEN  *Token
  );

struct EFI_TCP4_PROTOCOL {
  EFI_TCP4_RECEIVE_FN  Receive;
};

struct EFI_TCP6_PROTOCOL {
  EFI_TCP6_RECEIVE_FN  Receive;
};

struct _HTTP_PROTOCOL {
  BOOLEAN                LocalAddressIsIPv6;
  EFI_TCP4_PROTOCOL      *Tcp4;
  EFI_TCP6_PROTOCOL      *Tcp6;
  EFI_TCP4_IO_TOKEN      Tcp4TlsRxToken;
  EFI_TCP6_IO_TOKEN      Tcp6TlsRxToken;
  EFI_TLS_PROTOCOL       *Tls;
  EFI_TLS_SESSION_STATE  TlsSessionState;
};

VOID *
AllocateZeroPool (
  UINTN  AllocationSize
  );

static
UINT16
SwapBytes16 (
  UINT16  Value
  )
{
  return (UINT16)((Value << 8) | (Value >> 8));
}

EFI_STATUS
EFIAPI
TlsCommonTransmit (
  IN HTTP_PROTOCOL  *HttpInstance,
  IN NET_BUF        *Packet
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TlsCommonReceive (
  IN OUT HTTP_PROTOCOL  *HttpInstance,
  OUT NET_BUF           *Packet,
  IN EFI_EVENT          Timeout
  )
{
  EFI_TCP4_RECEIVE_DATA  *Tcp4RxData;
  EFI_TCP6_RECEIVE_DATA  *Tcp6RxData;
  EFI_STATUS             Status;
  NET_FRAGMENT           *Fragment;
  UINT32                 FragmentCount;
  UINT32                 CurrentFragment;

  Tcp4RxData = NULL;
  Tcp6RxData = NULL;

  if ((HttpInstance == NULL) || (Packet == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  FragmentCount = Packet->BlockOpNum;
  Fragment      = (NET_FRAGMENT *)AllocatePool (FragmentCount * sizeof (NET_FRAGMENT));
  if (Fragment == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = NetbufBuildExt (Packet, Fragment, &FragmentCount);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  if (!HttpInstance->LocalAddressIsIPv6) {
    Tcp4RxData = HttpInstance->Tcp4TlsRxToken.Packet.RxData;
    if (Tcp4RxData == NULL) {
      Status = EFI_INVALID_PARAMETER;
      goto ON_EXIT;
    }

    Tcp4RxData->FragmentCount = 1;
  } else {
    Tcp6RxData = HttpInstance->Tcp6TlsRxToken.Packet.RxData;
    if (Tcp6RxData == NULL) {
      Status = EFI_INVALID_PARAMETER;
      goto ON_EXIT;
    }

    Tcp6RxData->FragmentCount = 1;
  }

  CurrentFragment = 0;
  Status          = EFI_SUCCESS;

  while (CurrentFragment < FragmentCount) {
    if (!HttpInstance->LocalAddressIsIPv6) {
      Tcp4RxData->DataLength                       = Fragment[CurrentFragment].Len;
      Tcp4RxData->FragmentTable[0].FragmentLength = Fragment[CurrentFragment].Len;
      Tcp4RxData->FragmentTable[0].FragmentBuffer = Fragment[CurrentFragment].Bulk;
      Status                                      = HttpInstance->Tcp4->Receive (HttpInstance->Tcp4, &HttpInstance->Tcp4TlsRxToken);
      if (EFI_ERROR (Status)) {
        goto ON_EXIT;
      }

      Fragment[CurrentFragment].Len -= Tcp4RxData->FragmentTable[0].FragmentLength;
    } else {
      Tcp6RxData->DataLength                       = Fragment[CurrentFragment].Len;
      Tcp6RxData->FragmentTable[0].FragmentLength = Fragment[CurrentFragment].Len;
      Tcp6RxData->FragmentTable[0].FragmentBuffer = Fragment[CurrentFragment].Bulk;
      Status                                      = HttpInstance->Tcp6->Receive (HttpInstance->Tcp6, &HttpInstance->Tcp6TlsRxToken);
      if (EFI_ERROR (Status)) {
        goto ON_EXIT;
      }

      Fragment[CurrentFragment].Len -= Tcp6RxData->FragmentTable[0].FragmentLength;
    }

    if (Fragment[CurrentFragment].Len == 0) {
      CurrentFragment++;
    } else {
      if (!HttpInstance->LocalAddressIsIPv6) {
        Fragment[CurrentFragment].Bulk += Tcp4RxData->FragmentTable[0].FragmentLength;
      } else {
        Fragment[CurrentFragment].Bulk += Tcp6RxData->FragmentTable[0].FragmentLength;
      }
    }
  }

ON_EXIT:
  FreePool (Fragment);
  return Status;
}

EFI_STATUS
EFIAPI
TlsReceiveOnePdu (
  IN OUT HTTP_PROTOCOL  *HttpInstance,
  OUT NET_BUF           **Pdu,
  IN EFI_EVENT          Timeout
  )
{
  EFI_STATUS         Status;
  LIST_ENTRY         *NbufList;
  UINT32             Len;
  NET_BUF            *PduHdr;
  UINT8              *Header;
  TLS_RECORD_HEADER  RecordHeader;
  NET_BUF            *DataSeg;

  Status   = EFI_SUCCESS;
  NbufList = NULL;
  PduHdr   = NULL;
  Header   = NULL;
  DataSeg  = NULL;

  if ((HttpInstance == NULL) || (Pdu == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  NbufList = (LIST_ENTRY *)AllocatePool (sizeof (LIST_ENTRY));
  if (NbufList == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (NbufList);

  Len    = TLS_RECORD_HEADER_LENGTH;
  PduHdr = NetbufAlloc (Len);
  if (PduHdr == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  Header = NetbufAllocSpace (PduHdr, Len, NET_BUF_TAIL);
  if (Header == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  Status = TlsCommonReceive (HttpInstance, PduHdr, Timeout);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  RecordHeader = *(TLS_RECORD_HEADER *)Header;
  if (((RecordHeader.ContentType == TlsContentTypeHandshake) ||
       (RecordHeader.ContentType == TlsContentTypeAlert) ||
       (RecordHeader.ContentType == TlsContentTypeChangeCipherSpec) ||
       (RecordHeader.ContentType == TlsContentTypeApplicationData)) &&
      (RecordHeader.Version.Major == 0x03) &&
      ((RecordHeader.Version.Minor == TLS10_PROTOCOL_VERSION_MINOR) ||
       (RecordHeader.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
       (RecordHeader.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR)))
  {
    InsertTailList (NbufList, &PduHdr->List);
  } else {
    Status = EFI_PROTOCOL_ERROR;
    goto ON_EXIT;
  }

  Len = SwapBytes16 (RecordHeader.Length);
  if (Len == 0) {
    goto FORM_PDU;
  }

  DataSeg = NetbufAlloc (Len);
  if (DataSeg == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  if (NetbufAllocSpace (DataSeg, Len, NET_BUF_TAIL) == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  Status = TlsCommonReceive (HttpInstance, DataSeg, Timeout);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  InsertTailList (NbufList, &DataSeg->List);

FORM_PDU:
  *Pdu = NetbufFromBufList (NbufList, 0, 0, FreeNbufList, NbufList);
  if (*Pdu == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
  }

ON_EXIT:
  if (EFI_ERROR (Status)) {
    FreeNbufList (NbufList);
  }

  return Status;
}

EFI_STATUS
EFIAPI
TlsProcessMessage (
  IN HTTP_PROTOCOL       *HttpInstance,
  IN UINT8               *Message,
  IN UINTN               MessageSize,
  IN EFI_TLS_CRYPT_MODE  ProcessMode,
  IN OUT NET_FRAGMENT    *Fragment
  )
{
  if ((HttpInstance == NULL) || (Message == NULL) || (Fragment == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Fragment->Bulk = (UINT8 *)AllocateZeroPool (MessageSize);
  if (Fragment->Bulk == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Fragment->Len = (UINT32)MessageSize;
  CopyMem (Fragment->Bulk, Message, MessageSize);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
HttpsReceive (
  IN HTTP_PROTOCOL     *HttpInstance,
  IN OUT NET_FRAGMENT  *Fragment,
  IN EFI_EVENT         Timeout
  )
{
  EFI_STATUS         Status;
  NET_BUF            *Pdu;
  TLS_RECORD_HEADER  RecordHeader;
  UINT8              *BufferIn;
  UINTN              BufferInSize;
  NET_FRAGMENT       TempFragment;
  UINT8              *BufferOut;
  UINTN              BufferOutSize;
  NET_BUF            *PacketOut;
  UINT8              *DataOut;
  UINT8              *GetSessionDataBuffer;
  UINTN              GetSessionDataBufferSize;

  Status                   = EFI_SUCCESS;
  Pdu                      = NULL;
  BufferIn                 = NULL;
  BufferInSize             = 0;
  TempFragment.Bulk        = NULL;
  TempFragment.Len         = 0;
  BufferOut                = NULL;
  BufferOutSize            = 0;
  PacketOut                = NULL;
  DataOut                  = NULL;
  GetSessionDataBuffer     = NULL;
  GetSessionDataBufferSize = 0;

  Status = TlsReceiveOnePdu (HttpInstance, &Pdu, Timeout);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  BufferInSize = Pdu->TotalSize;
  BufferIn     = (UINT8 *)AllocateZeroPool (BufferInSize);
  if (BufferIn == NULL) {
    NetbufFree (Pdu);
    return EFI_OUT_OF_RESOURCES;
  }

  NetbufCopy (Pdu, 0, (UINT32)BufferInSize, BufferIn);
  NetbufFree (Pdu);

  RecordHeader = *(TLS_RECORD_HEADER *)BufferIn;

  if ((RecordHeader.ContentType == TlsContentTypeApplicationData) &&
      (RecordHeader.Version.Major == 0x03) &&
      ((RecordHeader.Version.Minor == TLS10_PROTOCOL_VERSION_MINOR) ||
       (RecordHeader.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
       (RecordHeader.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR)))
  {
    Status = TlsProcessMessage (HttpInstance, BufferIn, BufferInSize, EfiTlsDecrypt, &TempFragment);
    FreePool (BufferIn);

    if (EFI_ERROR (Status)) {
      if (Status == EFI_ABORTED) {
        BufferOutSize = DEF_BUF_LEN;
        BufferOut     = (UINT8 *)AllocateZeroPool (BufferOutSize);
        if (BufferOut == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }

        Status = HttpInstance->Tls->BuildResponsePacket (
                                     HttpInstance->Tls,
                                     NULL,
                                     0,
                                     BufferOut,
                                     &BufferOutSize
                                     );
        if (EFI_ERROR (Status)) {
          FreePool (BufferOut);
          return Status;
        }

        if (BufferOutSize != 0) {
          PacketOut = NetbufAlloc ((UINT32)BufferOutSize);
          if (PacketOut == NULL) {
            FreePool (BufferOut);
            return EFI_OUT_OF_RESOURCES;
          }

          DataOut = NetbufAllocSpace (PacketOut, (UINT32)BufferOutSize, NET_BUF_TAIL);
          if (DataOut == NULL) {
            FreePool (BufferOut);
            return EFI_OUT_OF_RESOURCES;
          }

          CopyMem (DataOut, BufferOut, BufferOutSize);
          Status = TlsCommonTransmit (HttpInstance, PacketOut);
          NetbufFree (PacketOut);
        }

        FreePool (BufferOut);
        return Status;
      }

      return Status;
    }

    ASSERT (((TLS_RECORD_HEADER *)(TempFragment.Bulk))->ContentType == TlsContentTypeApplicationData);

    BufferInSize = ((TLS_RECORD_HEADER *)(TempFragment.Bulk))->Length;
    BufferIn     = (UINT8 *)AllocateZeroPool (BufferInSize);
    if (BufferIn == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (BufferIn, TempFragment.Bulk + TLS_RECORD_HEADER_LENGTH, BufferInSize);
    FreePool (TempFragment.Bulk);
  } else if ((RecordHeader.ContentType == TlsContentTypeAlert) &&
             (RecordHeader.Version.Major == 0x03) &&
             ((RecordHeader.Version.Minor == TLS10_PROTOCOL_VERSION_MINOR) ||
              (RecordHeader.Version.Minor == TLS11_PROTOCOL_VERSION_MINOR) ||
              (RecordHeader.Version.Minor == TLS12_PROTOCOL_VERSION_MINOR)))
  {
    BufferOutSize = DEF_BUF_LEN;
    BufferOut     = (UINT8 *)AllocateZeroPool (BufferOutSize);
    if (BufferOut == NULL) {
      FreePool (BufferIn);
      return EFI_OUT_OF_RESOURCES;
    }

    Status = HttpInstance->Tls->BuildResponsePacket (
                                 HttpInstance->Tls,
                                 BufferIn,
                                 BufferInSize,
                                 BufferOut,
                                 &BufferOutSize
                                 );
    FreePool (BufferIn);

    if (EFI_ERROR (Status)) {
      FreePool (BufferOut);
      return Status;
    }

    if (BufferOutSize != 0) {
      PacketOut = NetbufAlloc ((UINT32)BufferOutSize);
      if (PacketOut == NULL) {
        FreePool (BufferOut);
        return EFI_OUT_OF_RESOURCES;
      }

      DataOut = NetbufAllocSpace (PacketOut, (UINT32)BufferOutSize, NET_BUF_TAIL);
      if (DataOut == NULL) {
        FreePool (BufferOut);
        return EFI_OUT_OF_RESOURCES;
      }

      CopyMem (DataOut, BufferOut, BufferOutSize);
      Status = TlsCommonTransmit (HttpInstance, PacketOut);
      NetbufFree (PacketOut);
    }

    FreePool (BufferOut);

    GetSessionDataBufferSize = sizeof (EFI_TLS_SESSION_STATE);
    GetSessionDataBuffer     = (UINT8 *)AllocateZeroPool (GetSessionDataBufferSize);
    if (GetSessionDataBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = HttpInstance->Tls->GetSessionData (
                                 HttpInstance->Tls,
                                 EfiTlsSessionState,
                                 GetSessionDataBuffer,
                                 &GetSessionDataBufferSize
                                 );
    if (EFI_ERROR (Status)) {
      FreePool (GetSessionDataBuffer);
      return Status;
    }

    HttpInstance->TlsSessionState = *(EFI_TLS_SESSION_STATE *)GetSessionDataBuffer;
    FreePool (GetSessionDataBuffer);

    if (HttpInstance->TlsSessionState == EfiTlsSessionError) {
      return EFI_ABORTED;
    }

    BufferIn     = NULL;
    BufferInSize = 0;
  }

  Fragment->Bulk = BufferIn;
  Fragment->Len  = (UINT32)BufferInSize;
  return Status;
}

#endif
