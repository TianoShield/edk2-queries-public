#ifndef TEST_INCLUDE_TLSPROTOCOL_C
#define TEST_INCLUDE_TLSPROTOCOL_C

#include "NetBuffer.c"

typedef enum {
  EfiTlsDecrypt
} EFI_TLS_CRYPT_MODE;

typedef enum {
  EfiTlsSessionNotStarted,
  EfiTlsSessionHandShaking,
  EfiTlsSessionDataTransferring,
  EfiTlsSessionClosing,
  EfiTlsSessionError,
  EfiTlsSessionStateMaximum
} EFI_TLS_SESSION_STATE;

typedef enum {
  EfiTlsSessionState
} EFI_TLS_SESSION_DATA_TYPE;

typedef struct {
  UINT8  Major;
  UINT8  Minor;
} EFI_TLS_VERSION;

typedef struct _EFI_TLS_PROTOCOL EFI_TLS_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_TLS_BUILD_RESPONSE_PACKET) (
  IN EFI_TLS_PROTOCOL  *This,
  IN UINT8             *RequestBuffer OPTIONAL,
  IN UINTN             RequestSize OPTIONAL,
  OUT UINT8            *Buffer OPTIONAL,
  IN OUT UINTN         *BufferSize
  );

typedef
EFI_STATUS
(EFIAPI *EFI_TLS_GET_SESSION_DATA) (
  IN EFI_TLS_PROTOCOL          *This,
  IN EFI_TLS_SESSION_DATA_TYPE DataType,
  OUT VOID                     *Data,
  IN OUT UINTN                 *DataSize
  );

struct _EFI_TLS_PROTOCOL {
  VOID                           *SetSessionData;
  EFI_TLS_GET_SESSION_DATA       GetSessionData;
  EFI_TLS_BUILD_RESPONSE_PACKET  BuildResponsePacket;
  VOID                           *ProcessPacket;
};

EFI_STATUS
EFIAPI
TlsDoHandshake (
  IN EFI_TLS_PROTOCOL  *This,
  IN UINT8             *BufferIn OPTIONAL,
  IN UINTN             BufferInSize OPTIONAL,
  OUT UINT8            *BufferOut OPTIONAL,
  IN OUT UINTN         *BufferOutSize
  )
{
  if (BufferOutSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (*BufferOutSize < BufferInSize) {
    *BufferOutSize = BufferInSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if ((BufferIn != NULL) && (BufferOut != NULL) && (BufferInSize != 0)) {
    CopyMem (BufferOut, BufferIn, BufferInSize);
  }

  *BufferOutSize = BufferInSize;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TlsHandleAlert (
  IN EFI_TLS_PROTOCOL  *This,
  IN UINT8             *BufferIn OPTIONAL,
  IN UINTN             BufferInSize OPTIONAL,
  OUT UINT8            *BufferOut OPTIONAL,
  IN OUT UINTN         *BufferOutSize
  )
{
  if (BufferOutSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (*BufferOutSize < BufferInSize) {
    *BufferOutSize = BufferInSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if ((BufferIn != NULL) && (BufferOut != NULL) && (BufferInSize != 0)) {
    CopyMem (BufferOut, BufferIn, BufferInSize);
  }

  *BufferOutSize = BufferInSize;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TlsBuildResponsePacket (
  IN EFI_TLS_PROTOCOL  *This,
  IN UINT8             *RequestBuffer OPTIONAL,
  IN UINTN             RequestSize OPTIONAL,
  OUT UINT8            *Buffer OPTIONAL,
  IN OUT UINTN         *BufferSize
  )
{
  if ((RequestBuffer == NULL) && (RequestSize == 0)) {
    return TlsDoHandshake (This, NULL, 0, Buffer, BufferSize);
  }

  return TlsHandleAlert (This, RequestBuffer, RequestSize, Buffer, BufferSize);
}

#endif
