#include "../include/NetBuffer.c"

typedef struct {
  UINT8     OpCode;
  UINT8     Reserved1[3];
  UINT8     TotalAHSLength;
  UINT8     DataSegmentLength[3];
  UINT8     Lun[8];
  UINT32    InitiatorTaskTag;
  UINT32    TargetTransferTag;
  UINT32    StatSN;
  UINT32    ExpCmdSN;
  UINT32    MaxCmdSN;
  UINT32    R2TSeqNum;
  UINT32    BufferOffset;
  UINT32    DesiredDataTransferLength;
} ISCSI_READY_TO_TRANSFER;

typedef struct {
  UINT32    TargetTransferTag;
  UINT32    Offset;
  UINT32    DesiredLength;
  UINT32    ExpDataSN;
} ISCSI_XFER_CONTEXT;

typedef struct {
  ISCSI_XFER_CONTEXT    XferContext;
} ISCSI_TCB;

typedef struct {
  UINT32    OutTransferLength;
} SCSI_REQUEST_PACKET;

EFI_STATUS
TcpIoReceive (
  IN VOID       *TcpIo,
  IN NET_BUF    *Packet,
  IN BOOLEAN    AsyncMode,
  IN EFI_EVENT  TimeoutEvent
  );

EFI_STATUS
IScsiReceivePdu (
  IN VOID       *Conn,
  OUT NET_BUF   **Pdu,
  IN VOID       *Context OPTIONAL,
  IN BOOLEAN    HeaderDigest,
  IN BOOLEAN    DataDigest,
  IN EFI_EVENT  TimeoutEvent OPTIONAL
  );

EFI_STATUS
SafeUint32Add (
  IN UINT32   Augend,
  IN UINT32   Addend,
  OUT UINT32  *Result
  );

UINT32
SwapBytes32 (
  IN UINT32  Value
  )
{
  return Value;
}

#define NTOHL(x)  SwapBytes32 (x)

EFI_STATUS
IScsiOnR2TRcvd_BAD (
  IN NET_BUF              *Pdu,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  ISCSI_XFER_CONTEXT       *XferContext;

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return EFI_PROTOCOL_ERROR;
  }

  R2THdr->BufferOffset              = NTOHL (R2THdr->BufferOffset);
  R2THdr->DesiredDataTransferLength = NTOHL (R2THdr->DesiredDataTransferLength);

  XferContext                = &Tcb->XferContext;
  XferContext->Offset        = R2THdr->BufferOffset;
  XferContext->DesiredLength = R2THdr->DesiredDataTransferLength;

  if ((XferContext->Offset + XferContext->DesiredLength) > Packet->OutTransferLength) {
    return EFI_PROTOCOL_ERROR;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
IScsiOnR2TRcvd_GOOD (
  IN NET_BUF              *Pdu,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  ISCSI_XFER_CONTEXT       *XferContext;
  EFI_STATUS               Status;
  UINT32                   TransferLength;

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return EFI_PROTOCOL_ERROR;
  }

  R2THdr->BufferOffset              = NTOHL (R2THdr->BufferOffset);
  R2THdr->DesiredDataTransferLength = NTOHL (R2THdr->DesiredDataTransferLength);

  XferContext                = &Tcb->XferContext;
  XferContext->Offset        = R2THdr->BufferOffset;
  XferContext->DesiredLength = R2THdr->DesiredDataTransferLength;

  Status = SafeUint32Add (XferContext->Offset, XferContext->DesiredLength, &TransferLength);
  if (EFI_ERROR (Status)) {
    return EFI_PROTOCOL_ERROR;
  }

  if (TransferLength > Packet->OutTransferLength) {
    return EFI_PROTOCOL_ERROR;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
ReceiveAndProcess_BAD (
  IN VOID                 *TcpIo,
  IN NET_BUF              *Pdu,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  EFI_STATUS  Status;

  Status = TcpIoReceive (TcpIo, Pdu, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return IScsiOnR2TRcvd_BAD (Pdu, Tcb, Packet);
}

EFI_STATUS
ReceiveAndProcess_GOOD (
  IN VOID                 *TcpIo,
  IN NET_BUF              *Pdu,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  EFI_STATUS  Status;

  Status = TcpIoReceive (TcpIo, Pdu, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return IScsiOnR2TRcvd_GOOD (Pdu, Tcb, Packet);
}

EFI_STATUS
ReceiveAndProcessFromIscsiReceivePdu_BAD (
  IN VOID                 *Conn,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return IScsiOnR2TRcvd_BAD (Pdu, Tcb, Packet);
}

EFI_STATUS
ReceiveAndProcessFromIscsiReceivePdu_GOOD (
  IN VOID                 *Conn,
  IN ISCSI_TCB            *Tcb,
  IN SCSI_REQUEST_PACKET  *Packet
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return IScsiOnR2TRcvd_GOOD (Pdu, Tcb, Packet);
}

//
// CVE-2023-45229 — DHCP6 inner-option-length underflow. A length parsed out of
// the received packet via `NTOHS (ReadUnaligned16 (...))` has a fixed header
// size subtracted with no minimum-size check, and the result is reinterpreted
// as unsigned; when the parsed length is below the fixed size the subtraction
// goes negative and wraps to a huge length, driving an out-of-bounds read.
//
// These cases also exercise the `SwapBytes16` taint model: its swap body
// (`(hi << 8) | (lo >> 8)`) is removed by the both-operands-non-constant
// barrier, so an explicit model is required for the parsed length to stay
// tainted across `NTOHS`. The wrap is width-independent (a widening cast wraps
// too), so detection does not key on the result type; precision instead comes
// from a lower-bound guard check.
//
UINT16
SwapBytes16 (
  IN UINT16  Value
  )
{
  return (UINT16)((Value << 8) | (Value >> 8));
}

#define NTOHS(x)  SwapBytes16 (x)

UINT16
ReadUnaligned16 (
  IN UINT16  *Buffer
  )
{
  return *Buffer;
}

typedef struct {
  UINT16    Reserved;
  UINT16    OptLen;
} DHCP6_OPT_HDR;

// BAD: unguarded `NTOHS (option-len) - 12` narrowed to UINT16.
UINT16
Dhcp6InnerOptionLen_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;
  UINT8       *Option;
  UINT16      IaInnerLen;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Option = NetbufGetByte (Pdu, 0, NULL);
  if (Option == NULL) {
    return 0;
  }

  IaInnerLen = (UINT16)(NTOHS (ReadUnaligned16 ((UINT16 *)(Option + 2))) - 12);
  return IaInnerLen;
}

// BAD: the same unguarded subtraction kept wide (UINTN). A widening cast wraps a
// sign flip just as badly as a narrowing one, so this is a true positive too.
UINTN
Dhcp6InnerOptionLen_Widen_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;
  UINT8       *Option;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Option = NetbufGetByte (Pdu, 0, NULL);
  if (Option == NULL) {
    return 0;
  }

  return (UINTN)(NTOHS (ReadUnaligned16 ((UINT16 *)(Option + 2))) - 12);
}

// GOOD: a dominating minimum-size guard on a local clears the underflow via
// range analysis (`convertedExprMightOverflowNegatively` becomes false).
UINT16
Dhcp6InnerOptionLen_Guard_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;
  UINT8       *Option;
  UINT16      OptionLen;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Option = NetbufGetByte (Pdu, 0, NULL);
  if (Option == NULL) {
    return 0;
  }

  OptionLen = NTOHS (ReadUnaligned16 ((UINT16 *)(Option + 2)));
  if (OptionLen < 12) {
    return 0;
  }

  return (UINT16)(OptionLen - 12);
}

// GOOD: here the minimum-size guard is on a *struct field*, not a local, so
// range analysis cannot clear it; the GuardCondition.ensuresLt lower-bound check
// does. Mirrors the safe `RelocDir->Size - 1` under `if (RelocDir->Size > 0)`.
UINTN
Dhcp6InnerOptionLen_FieldGuard_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS     Status;
  NET_BUF        *Pdu;
  DHCP6_OPT_HDR  *Hdr;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Hdr = (DHCP6_OPT_HDR *)NetbufGetByte (Pdu, 0, NULL);
  if (Hdr == NULL) {
    return 0;
  }

  if (Hdr->OptLen < 12) {
    return 0;
  }

  return (UINTN)(Hdr->OptLen - 12);
}

//
// CVE-2022-36765 — `HobLength + 0x7` overflows when the caller-supplied
// `HobLength` is close to MAX_UINT16. The BAD variant matches the
// pre-patch EDK II `CreateHob`; the GOOD variant adds the
// `HobLength > MAX_UINT16 - 0x7` headroom check that the upstream fix
// introduced.
//
#define MAX_UINT16  ((UINT16)0xFFFF)

typedef unsigned long long UINT64;

typedef struct {
  UINT64    EfiFreeMemoryTop;
  UINT64    EfiFreeMemoryBottom;
  UINT64    EfiEndOfHobList;
} HOB_HANDOFF;

HOB_HANDOFF *
GetHobList (
  VOID
  );

VOID *
CreateHob (
  IN  UINT16  HobType,
  IN  UINT16  HobLength
  )
{
  HOB_HANDOFF  *HandOffHob;
  UINT64       FreeMemory;
  VOID         *Hob;

  HandOffHob = GetHobList ();

  HobLength = (UINT16)((HobLength + 0x7) & (~0x7));

  FreeMemory = HandOffHob->EfiFreeMemoryTop - HandOffHob->EfiFreeMemoryBottom;
  if (FreeMemory < HobLength) {
    return NULL;
  }

  Hob                         = (VOID *)(UINTN)HandOffHob->EfiEndOfHobList;
  HandOffHob->EfiEndOfHobList = HandOffHob->EfiEndOfHobList + HobLength;
  return Hob;
}

#define MAX_UINT32  ((UINT32)0xFFFFFFFF)

//
// CVE-2024-38796 — `RelocDir->VirtualAddress + RelocDir->Size - 1` in
// `PeCoffLoaderRelocateImage` wraps mod 2^32 when both fields come from
// an attacker-supplied PE/COFF header. The header bytes enter the loaded
// image buffer through a call to the `PE_COFF_LOADER_READ_FILE` callback
// stashed on `ImageContext->ImageRead`; the buffer arg of that call is
// `(VOID *)(UINTN)ImageContext->ImageAddress`, and subsequent reads through
// the reinterpret-cast header pointer carry the same attacker-controlled
// bytes.
//
typedef struct {
  UINT32  VirtualAddress;
  UINT32  Size;
} EFI_IMAGE_DATA_DIRECTORY;

typedef struct {
  UINT32                    Magic;
  EFI_IMAGE_DATA_DIRECTORY  DataDirectory[16];
} EFI_IMAGE_OPTIONAL_HEADER32;

typedef struct {
  UINT32                       Signature;
  EFI_IMAGE_OPTIONAL_HEADER32  OptionalHeader;
} EFI_IMAGE_NT_HEADERS32;

typedef struct {
  UINT16                    Magic;
  UINT16                    StrippedSize;
  UINT32                    AddressOfEntryPoint;
  UINT32                    BaseOfCode;
  UINT64                    ImageBase;
  EFI_IMAGE_DATA_DIRECTORY  DataDirectory[2];
} EFI_TE_IMAGE_HEADER;

typedef struct {
  UINT8     Name[8];
  union {
    UINT32  PhysicalAddress;
    UINT32  VirtualSize;
  } Misc;
  UINT32    VirtualAddress;
  UINT32    SizeOfRawData;
  UINT32    PointerToRawData;
} EFI_IMAGE_SECTION_HEADER;

typedef EFI_STATUS (EFIAPI *PE_COFF_LOADER_READ_FILE)(
  IN VOID *FileHandle, IN UINTN FileOffset, IN OUT UINTN *ReadSize, OUT VOID *Buffer);

typedef struct {
  UINTN                     ImageAddress;
  UINT64                    ImageSize;
  UINTN                     DestinationAddress;
  UINTN                     EntryPoint;
  PE_COFF_LOADER_READ_FILE  ImageRead;
  VOID                      *Handle;
  VOID                      *FixupData;
  UINT32                    SectionAlignment;
  UINT32                    PeCoffHeaderOffset;
  UINTN                     SizeOfHeaders;
} PE_COFF_LOADER_IMAGE_CONTEXT;

VOID *
PeCoffLoaderImageAddress (
  IN PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  IN UINT32                         Address,
  IN UINT32                         TeStrippedOffset
  );

EFI_STATUS
PeCoffLoaderLoadImage (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  );

//
// Function-local source: the `ImageRead` call sits in the same function as
// the unguarded `RelocDir->VirtualAddress + RelocDir->Size - 1` addition.
// Attacker-controlled bytes flow Buffer → ImageContext->ImageAddress →
// (cast) → Hdr->OptionalHeader.DataDirectory[5].{VirtualAddress,Size}.
//
VOID
PeCoffLoaderRelocateImage_RelocDir_BAD (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  EFI_IMAGE_NT_HEADERS32    *Hdr;
  EFI_IMAGE_DATA_DIRECTORY  *RelocDir;
  UINTN                     ReadSize;

  ReadSize = sizeof (EFI_IMAGE_NT_HEADERS32);
  ImageContext->ImageRead (
                  ImageContext->Handle,
                  0,
                  &ReadSize,
                  (VOID *)(UINTN)ImageContext->ImageAddress
                  );

  Hdr      = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *)(UINTN)ImageContext->ImageAddress + ImageContext->PeCoffHeaderOffset);
  RelocDir = &Hdr->OptionalHeader.DataDirectory[5];

  if (RelocDir->Size > 0) {
    (VOID)PeCoffLoaderImageAddress (
            ImageContext,
            RelocDir->VirtualAddress + RelocDir->Size - 1,
            0
            );
  }
}

VOID
PeCoffLoaderRelocateImage_RelocDir_GOOD (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  EFI_IMAGE_NT_HEADERS32    *Hdr;
  EFI_IMAGE_DATA_DIRECTORY  *RelocDir;
  UINTN                     ReadSize;

  ReadSize = sizeof (EFI_IMAGE_NT_HEADERS32);
  ImageContext->ImageRead (
                  ImageContext->Handle,
                  0,
                  &ReadSize,
                  (VOID *)(UINTN)ImageContext->ImageAddress
                  );

  Hdr      = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *)(UINTN)ImageContext->ImageAddress + ImageContext->PeCoffHeaderOffset);
  RelocDir = &Hdr->OptionalHeader.DataDirectory[5];

  if ((RelocDir->Size > 0) &&
      (RelocDir->Size - 1 < MAX_UINT32 - RelocDir->VirtualAddress)) {
    (VOID)PeCoffLoaderImageAddress (
            ImageContext,
            RelocDir->VirtualAddress + RelocDir->Size - 1,
            0
            );
  }
}


VOID *
CreateHob_GOOD (
  IN  UINT16  HobType,
  IN  UINT16  HobLength
  )
{
  HOB_HANDOFF  *HandOffHob;
  UINT64       FreeMemory;
  VOID         *Hob;

  HandOffHob = GetHobList ();

  if (HobLength > MAX_UINT16 - 0x7) {
    return NULL;
  }

  HobLength = (UINT16)((HobLength + 0x7) & (~0x7));

  FreeMemory = HandOffHob->EfiFreeMemoryTop - HandOffHob->EfiFreeMemoryBottom;
  if (FreeMemory < HobLength) {
    return NULL;
  }

  Hob                         = (VOID *)(UINTN)HandOffHob->EfiEndOfHobList;
  HandOffHob->EfiEndOfHobList = HandOffHob->EfiEndOfHobList + HobLength;
  return Hob;
}

//
// `MAX_ADDRESS - X + 1` headroom idiom used by EDK II
// `MdeModulePkg/Library/.../MemoryAllocationLib.c`:
//
//   ASSERT (AllocationSize <= (MAX_ADDRESS - (UINTN)Buffer + 1));
//
// The `+ 1` arithmetic lives *inside* the bounds-check expression rather
// than in a basic block dominated by it, so the standard headroom-guard
// pattern (`controls`) does not match. Treat the `+ 1` as part of the
// headroom expression itself.
//
#define MAX_ADDRESS  ((UINTN)~0)

EFI_STATUS
AllocateCopyPool_GOOD (
  IN  VOID    *SourceBuffer,
  IN  UINTN   SourceSize
  )
{
  if (SourceSize > (MAX_ADDRESS - (UINTN)SourceBuffer + 1)) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

//
// CVE-2022-36764: TPM measure-boot `EventSize` integer overflow.
//
// The DXE core dispatches an untrusted image to a security file-authentication
// handler registered via `RegisterSecurity2Handler` / `RegisterSecurityHandler`,
// passing the image's device path as the `File` parameter (parameter index 1).
// The TPM measure-boot handlers size that device path with `GetDevicePathSize`
// and add the result to a fixed struct size with no overflow check, so the
// UINT32 `EventSize` wraps and the subsequent allocation is undersized.
//
// Source     : the `File` device-path parameter of a registered handler.
// Taint step : `GetDevicePathSize(arg[*0]) -> return`; `DuplicateDevicePath`
//              returns a fresh copy of the device-path bytes (`arg[*0] ->
//              return[*0]`).
//

typedef struct {
  UINT8    Type;
  UINT8    SubType;
  UINT8    Length[2];
} EFI_DEVICE_PATH_PROTOCOL;

typedef struct {
  UINTN                       ImageLocationInMemory;
  UINTN                       ImageLengthInMemory;
  UINTN                       ImageLinkTimeAddress;
  UINTN                       LengthOfDevicePath;
  EFI_DEVICE_PATH_PROTOCOL    DevicePath[1];
} EFI_IMAGE_LOAD_EVENT;

UINTN
GetDevicePathSize (
  const EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  );

EFI_DEVICE_PATH_PROTOCOL *
DuplicateDevicePath (
  const EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  );

VOID *
AllocateZeroPool (
  UINTN  AllocationSize
  );

typedef
EFI_STATUS
(EFIAPI *SECURITY2_FILE_AUTHENTICATION_HANDLER)(
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  IN  BOOLEAN                   BootPolicy
  );

typedef
EFI_STATUS
(EFIAPI *SECURITY_FILE_AUTHENTICATION_STATE_HANDLER)(
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize
  );

EFI_STATUS
RegisterSecurity2Handler (
  IN  SECURITY2_FILE_AUTHENTICATION_HANDLER  Security2Handler,
  IN  UINT32                                 AuthenticationOperation
  );

EFI_STATUS
RegisterSecurityHandler (
  IN  SECURITY_FILE_AUTHENTICATION_STATE_HANDLER  SecurityHandler,
  IN  UINT32                                      AuthenticationOperation
  );

//
// BAD: tainted device-path size added to a fixed struct size with no guard
// (the literal CVE-2022-36764 shape).
//
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage_BAD (
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  IN  BOOLEAN                   BootPolicy
  )
{
  UINT32                FilePathSize;
  UINT32                EventSize;
  EFI_IMAGE_LOAD_EVENT  *ImageLoad;

  FilePathSize = (UINT32)GetDevicePathSize (File);
  EventSize    = sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath) + FilePathSize;
  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// BAD: same overflow, but the device path is duplicated first. Exercises the
// `DuplicateDevicePath` content-to-content taint step.
//
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage_Duplicate_BAD (
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  IN  BOOLEAN                   BootPolicy
  )
{
  UINT32                    FilePathSize;
  UINT32                    EventSize;
  EFI_IMAGE_LOAD_EVENT      *ImageLoad;
  EFI_DEVICE_PATH_PROTOCOL  *OrigDevicePathNode;

  OrigDevicePathNode = DuplicateDevicePath (File);
  FilePathSize       = (UINT32)GetDevicePathSize (OrigDevicePathNode);
  EventSize          = sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath) + FilePathSize;
  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// BAD: TPM 1.2 sibling registered through `RegisterSecurityHandler` (the
// four-parameter handler). `File` is still parameter index 1.
//
EFI_STATUS
EFIAPI
TcgMeasurePeImage_BAD (
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize
  )
{
  UINT32                FilePathSize;
  UINT32                EventSize;
  EFI_IMAGE_LOAD_EVENT  *ImageLoad;

  FilePathSize = (UINT32)GetDevicePathSize (File);
  EventSize    = sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath) + FilePathSize;
  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// GOOD: upstream fix shape — the addition is performed by `SafeUint32Add`, so
// there is no unguarded `+` operand for the tainted size to reach.
//
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage_SafeAdd_GOOD (
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  IN  BOOLEAN                   BootPolicy
  )
{
  UINT32                FilePathSize;
  UINT32                EventSize;
  EFI_IMAGE_LOAD_EVENT  *ImageLoad;
  EFI_STATUS            Status;

  FilePathSize = (UINT32)GetDevicePathSize (File);
  Status       = SafeUint32Add (
                   sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath),
                   FilePathSize,
                   &EventSize
                   );
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// GOOD: explicit MAX_UINT32 headroom guard dominating the addition.
//
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage_Guard_GOOD (
  IN  UINT32                    AuthenticationStatus,
  IN  EFI_DEVICE_PATH_PROTOCOL  *File,
  IN  VOID                      *FileBuffer,
  IN  UINTN                     FileSize,
  IN  BOOLEAN                   BootPolicy
  )
{
  UINT32                FilePathSize;
  UINT32                EventSize;
  EFI_IMAGE_LOAD_EVENT  *ImageLoad;

  FilePathSize = (UINT32)GetDevicePathSize (File);
  if (FilePathSize > MAX_UINT32 - (sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath))) {
    return EFI_INVALID_PARAMETER;
  }

  EventSize = sizeof (*ImageLoad) - sizeof (ImageLoad->DevicePath) + FilePathSize;
  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// Registering each handler is what makes its `File` parameter an attacker-
// controlled source; the GOOD handlers are registered too so the absence of an
// alert reflects the guard/safe-add, not an untainted input.
//
VOID
RegisterTpmMeasureBootHandlers (
  VOID
  )
{
  RegisterSecurity2Handler (Tcg2MeasurePeImage_BAD, 0);
  RegisterSecurity2Handler (Tcg2MeasurePeImage_Duplicate_BAD, 0);
  RegisterSecurity2Handler (Tcg2MeasurePeImage_SafeAdd_GOOD, 0);
  RegisterSecurity2Handler (Tcg2MeasurePeImage_Guard_GOOD, 0);
  RegisterSecurityHandler (TcgMeasurePeImage_BAD, 0);
}

//
// CVE-2022-36763: TPM measure-boot GPT-table integer overflow.
//
// `Tcg2MeasureGptTable` (and the TPM 1.2 sibling `TcgMeasureGptTable`) read an
// untrusted GPT primary header off disk via `DiskIo->ReadDisk` (or
// `BlockIo->ReadBlocks`) and then size allocations with the unchecked product
// `NumberOfPartitionEntries * SizeOfPartitionEntry`, so the UINT32 result wraps
// and the allocation is undersized.
//
// Source     : the `Buffer` output (argument index 4) of `ReadDisk`/`ReadBlocks`.
// Taint step : the disk-read buffer content inherits into the size-controlling
//              `EFI_PARTITION_TABLE_HEADER` fields (TaintInheritingContent).
//

typedef unsigned long long UINT64;
typedef UINT64             EFI_LBA;
#define MAX_UINT64  ((UINT64)0xFFFFFFFFFFFFFFFFULL)

typedef struct {
  UINT64     Signature;
  EFI_LBA    MyLBA;
  EFI_LBA    PartitionEntryLBA;
  UINT32     NumberOfPartitionEntries;
  UINT32     SizeOfPartitionEntry;
} EFI_PARTITION_TABLE_HEADER;

typedef struct _EFI_DISK_IO_PROTOCOL EFI_DISK_IO_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_DISK_READ)(
  IN  EFI_DISK_IO_PROTOCOL  *This,
  IN  UINT32                MediaId,
  IN  UINT64                Offset,
  IN  UINTN                 BufferSize,
  OUT VOID                  *Buffer
  );

struct _EFI_DISK_IO_PROTOCOL {
  UINT64           Revision;
  EFI_DISK_READ    ReadDisk;
};

typedef struct _EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_BLOCK_READ)(
  IN  EFI_BLOCK_IO_PROTOCOL  *This,
  IN  UINT32                 MediaId,
  IN  EFI_LBA                Lba,
  IN  UINTN                  BufferSize,
  OUT VOID                   *Buffer
  );

struct _EFI_BLOCK_IO_PROTOCOL {
  UINT64            Revision;
  EFI_BLOCK_READ    ReadBlocks;
};

VOID *
AllocatePool (
  UINTN  AllocationSize
  );

EFI_STATUS
SafeUint32Mult (
  IN  UINT32   Multiplicand,
  IN  UINT32   Multiplier,
  OUT UINT32   *Result
  );

UINT64
DivU64x32 (
  IN  UINT64  Dividend,
  IN  UINT32  Divisor
  );

//
// BAD: GPT primary header read from disk, then the partition-entry array is
// sized by the unchecked product (the literal CVE-2022-36763 allocation shape).
//
EFI_STATUS
EFIAPI
Tcg2MeasureGptTable_BAD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  VOID                        *EntryPtr;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  EntryPtr = AllocatePool (PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry);
  if (EntryPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// BAD: the product feeds the enclosing `EventSize` addition. The flagged
// operand is the multiply's field read, upstream of both the `*` and the `+`,
// so the "both operands non-constant" barrier on the multiply result does not
// suppress it.
//
EFI_STATUS
EFIAPI
Tcg2MeasureGptTable_EventSize_BAD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT32                      EventSize;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  EventSize = sizeof (EFI_PARTITION_TABLE_HEADER)
              + PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry;
  if (AllocateZeroPool (EventSize) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// BAD: same overflow, but the header is read through `BlockIo->ReadBlocks`,
// exercising the block-I/O source.
//
EFI_STATUS
EFIAPI
MeasureGptViaBlockIo_BAD (
  IN  EFI_BLOCK_IO_PROTOCOL  *BlockIo,
  IN  UINT32                 MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  VOID                        *EntryPtr;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  BlockIo->ReadBlocks (BlockIo, MediaId, 1, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  EntryPtr = AllocatePool (PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry);
  if (EntryPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// GOOD: upstream fix shape — the product is computed by `SafeUint32Mult`, so
// there is no raw `*` operand for the tainted size to reach.
//
EFI_STATUS
EFIAPI
Tcg2MeasureGptTable_SafeMult_GOOD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  VOID                        *EntryPtr;
  UINT32                      AllocSize;
  EFI_STATUS                  Status;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  Status = SafeUint32Mult (
             PrimaryHeader->NumberOfPartitionEntries,
             PrimaryHeader->SizeOfPartitionEntry,
             &AllocSize
             );
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  EntryPtr = AllocatePool (AllocSize);
  if (EntryPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// GOOD: division-based headroom guard mentioning MAX_UINT64 dominates the
// product (the real fix's `SanitizeEfiPartitionTableHeader` shape).
//
EFI_STATUS
EFIAPI
Tcg2MeasureGptTable_Guard_GOOD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  VOID                        *EntryPtr;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  if (PrimaryHeader->NumberOfPartitionEntries >
      DivU64x32 (MAX_UINT64, PrimaryHeader->SizeOfPartitionEntry))
  {
    return EFI_INVALID_PARAMETER;
  }

  EntryPtr = AllocatePool (PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry);
  if (EntryPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// BaseLib fixed-width multiply chain. `MultU64x32` forwards to
// `InternalMathMultU64x32`, whose `Multiplicand * Multiplier` is the operation
// that can overflow. The query must NOT report inside this internal helper; it
// reports at the wrapper call site instead.
//
UINT64
InternalMathMultU64x32 (
  IN  UINT64  Multiplicand,
  IN  UINT32  Multiplier
  )
{
  return Multiplicand * Multiplier;
}

UINT64
MultU64x32 (
  IN  UINT64  Multiplicand,
  IN  UINT32  Multiplier
  )
{
  UINT64  Result;

  Result = InternalMathMultU64x32 (Multiplicand, Multiplier);

  return Result;
}

//
// BAD: the disk-controlled partition-entry LBA is scaled to a byte offset by
// `MultU64x32`. The flagged operand is the tainted factor argument at the call
// site, not the multiply inside `InternalMathMultU64x32`.
//
EFI_STATUS
EFIAPI
MeasureGptViaMultU64x32_BAD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT64                      Offset;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  Offset = MultU64x32 (PrimaryHeader->PartitionEntryLBA, 512);
  DiskIo->ReadDisk (DiskIo, MediaId, Offset, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  return EFI_SUCCESS;
}

//
// BAD: both factor arguments are disk-controlled, so each is flagged at the
// call site (mirrors the FPDT `MultU64x32 (AverageResume, ResumeCount)` shape
// where both operands carry taint).
//
EFI_STATUS
EFIAPI
MultU64x32_BothTainted_BAD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT64                      Total;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  Total = MultU64x32 (PrimaryHeader->PartitionEntryLBA, PrimaryHeader->NumberOfPartitionEntries);
  if (AllocateZeroPool (Total) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

//
// GOOD: the disk-controlled LBA is upper-bounded before being scaled, so the
// upper-bound barrier blocks flow to the `MultU64x32` factor argument.
//
EFI_STATUS
EFIAPI
MeasureGptViaMultU64x32_Guard_GOOD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT64                      Lba;
  UINT64                      Offset;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  Lba = PrimaryHeader->PartitionEntryLBA;
  if (Lba < 0x100000) {
    Offset = MultU64x32 (Lba, 512);
    DiskIo->ReadDisk (DiskIo, MediaId, Offset, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);
  }

  return EFI_SUCCESS;
}

//
// GOOD: a MAX_UINT64 headroom guard dominates the `MultU64x32` call site. The
// tainted factor is a field access (not blocked by the local-variable
// upper-bound barrier), so suppression here relies on the call being treated
// as a multiplication and recognized as overflow-guarded by `hasOverflowGuard`.
//
EFI_STATUS
EFIAPI
MeasureGptViaMultU64x32_HeadroomGuard_GOOD (
  IN  EFI_DISK_IO_PROTOCOL  *DiskIo,
  IN  UINT32                MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT64                      Offset;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  if (PrimaryHeader->PartitionEntryLBA < DivU64x32 (MAX_UINT64, 512)) {
    Offset = MultU64x32 (PrimaryHeader->PartitionEntryLBA, 512);
    DiskIo->ReadDisk (DiskIo, MediaId, Offset, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);
  }

  return EFI_SUCCESS;
}

//
// GPT partition-table-header sanitizer (the real DxeTpmMeasureBootLib helper):
// a successful return bounds PartitionEntryLBA / NumberOfPartitionEntries
// against MAX_UINT64.
//
EFI_STATUS
EFIAPI
TpmSanitizeEfiPartitionTableHeader (
  IN  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader,
  IN  EFI_BLOCK_IO_PROTOCOL       *BlockIo
  );

//
// GOOD: a successful `TpmSanitizeEfiPartitionTableHeader` call on the header
// dominates the `MultU64x32`, bounding `PartitionEntryLBA` against MAX_UINT64.
// The 64-bit product cannot overflow, so the call site is not flagged
// (the DxeTpm[2]MeasureBootLib false-positive shape).
//
EFI_STATUS
EFIAPI
MeasureGptViaMultU64x32_Sanitized_GOOD (
  IN  EFI_DISK_IO_PROTOCOL   *DiskIo,
  IN  EFI_BLOCK_IO_PROTOCOL  *BlockIo,
  IN  UINT32                 MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  UINT64                      Offset;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  if (EFI_ERROR (TpmSanitizeEfiPartitionTableHeader (PrimaryHeader, BlockIo))) {
    return EFI_INVALID_PARAMETER;
  }

  Offset = MultU64x32 (PrimaryHeader->PartitionEntryLBA, 512);
  DiskIo->ReadDisk (DiskIo, MediaId, Offset, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  return EFI_SUCCESS;
}

//
// BAD: the same sanitizer dominates, but the overflow here is the UINT32
// `NumberOfPartitionEntries * SizeOfPartitionEntry` allocation product
// (CVE-2022-36763). The sanitizer's MAX_UINT64 bound does not prevent a UINT32
// wrap, so the sanitizer suppression must NOT reach this raw multiply.
//
EFI_STATUS
EFIAPI
MeasureGptSanitizedButU32Mult_BAD (
  IN  EFI_DISK_IO_PROTOCOL   *DiskIo,
  IN  EFI_BLOCK_IO_PROTOCOL  *BlockIo,
  IN  UINT32                 MediaId
  )
{
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  VOID                        *EntryPtr;

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)AllocatePool (sizeof (*PrimaryHeader));
  DiskIo->ReadDisk (DiskIo, MediaId, 0, sizeof (*PrimaryHeader), (UINT8 *)PrimaryHeader);

  if (EFI_ERROR (TpmSanitizeEfiPartitionTableHeader (PrimaryHeader, BlockIo))) {
    return EFI_INVALID_PARAMETER;
  }

  EntryPtr = AllocatePool (PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry);
  if (EntryPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

// ===== CVE-2023-45232 / CVE-2023-45233: IP6 extension-header option parsing =====
//
// Ip6IsExtsValid()/Ip6IsOptionValid() parse attacker-controlled IPv6 extension
// header options delivered by MNP. The reverted fix narrowed the option-length
// and loop-offset arithmetic back to UINT8, so an attacker length byte
// truncates/wraps the 8-bit result and the parse loop fails to terminate
// (PixieFail #4/#5). The receive callback's NET_BUF parameter is the flow
// source: it is registered through Ip6ReceiveFrame and reaches the parser via
// NetbufGetByte. The GOOD cases keep the same arithmetic in a wide-enough type
// (the upstream fix), so the product/offset fits and is not flagged.

typedef
VOID
(*IP6_FRAME_CALLBACK) (
  IN NET_BUF     *Packet,
  IN EFI_STATUS  IoStatus,
  IN UINT32      Flag,
  IN VOID        *Context
  );

EFI_STATUS
Ip6ReceiveFrame (
  IN IP6_FRAME_CALLBACK  CallBack,
  IN VOID                *IpSb
  );

// BAD: Hdr-Ext-Len option length truncated to UINT8 — `(*Option + 1) * 8 - 2`
// reaches 2046 for a 0xFF length byte and wraps the 8-bit result.
VOID
Ip6AcceptFrame_ExtHdrLen_BAD (
  IN NET_BUF     *Packet,
  IN EFI_STATUS  IoStatus,
  IN UINT32      Flag,
  IN VOID        *Context
  )
{
  UINT8  *Option;
  UINT8  OptionLen;

  Option = NetbufGetByte (Packet, 2, NULL);
  if (Option == NULL) {
    return;
  }

  OptionLen = (UINT8)((*Option + 1) * 8 - 2);
  (VOID)OptionLen;
}

// GOOD: the same arithmetic kept in UINT16 (the upstream fix). The product
// (max 2046) fits the result type, so there is no truncation and no alert.
VOID
Ip6AcceptFrame_ExtHdrLen_GOOD (
  IN NET_BUF     *Packet,
  IN EFI_STATUS  IoStatus,
  IN UINT32      Flag,
  IN VOID        *Context
  )
{
  UINT8   *Option;
  UINT16  OptionLen;

  Option = NetbufGetByte (Packet, 2, NULL);
  if (Option == NULL) {
    return;
  }

  OptionLen = (UINT16)((*Option + 1) * 8 - 2);
  (VOID)OptionLen;
}

// BAD: PadN option offset advance truncated to UINT8 — an attacker data-length
// byte wraps the 8-bit loop offset (`Offset + *(Option + Offset + 1) + 2`).
VOID
Ip6AcceptFrame_OffsetWrap_BAD (
  IN NET_BUF     *Packet,
  IN EFI_STATUS  IoStatus,
  IN UINT32      Flag,
  IN VOID        *Context
  )
{
  UINT8  *Option;
  UINT8  Offset;

  Option = NetbufGetByte (Packet, 2, NULL);
  if (Option == NULL) {
    return;
  }

  Offset = 0;
  while (Offset < 40) {
    Offset = (UINT8)(Offset + *(Option + Offset + 1) + 2);
  }
}

// GOOD: the option data length is first read into a UINT8 local (so a single
// byte is not carried into arithmetic as a length) and the offset advances in
// UINT16, mirroring the patched IP6_NEXT_OPTION_OFFSET path. No truncating
// arithmetic on the attacker byte, so no alert.
VOID
Ip6AcceptFrame_OffsetWrap_GOOD (
  IN NET_BUF     *Packet,
  IN EFI_STATUS  IoStatus,
  IN UINT32      Flag,
  IN VOID        *Context
  )
{
  UINT8   *Option;
  UINT16  Offset;
  UINT8   OptDataLen;

  Option = NetbufGetByte (Packet, 2, NULL);
  if (Option == NULL) {
    return;
  }

  Offset = 0;
  while (Offset < 40) {
    OptDataLen = *(Option + Offset + 1);
    Offset     = (UINT16)(Offset + OptDataLen + 2);
  }
}

// Registers the callbacks above; the registration is what marks each callback's
// NET_BUF parameter as an attacker-controlled flow source.
VOID
Ip6RegisterReceive (
  IN VOID  *IpSb
  )
{
  Ip6ReceiveFrame (Ip6AcceptFrame_ExtHdrLen_BAD, IpSb);
  Ip6ReceiveFrame (Ip6AcceptFrame_ExtHdrLen_GOOD, IpSb);
  Ip6ReceiveFrame (Ip6AcceptFrame_OffsetWrap_BAD, IpSb);
  Ip6ReceiveFrame (Ip6AcceptFrame_OffsetWrap_GOOD, IpSb);
}

// Advances `*Cursor` by a tainted `OptLen`, mirroring Dhcp6AppendOption's
// `*PacketCursor += NTOHS (OptLen)`, which taints the cursor pointer.
static
VOID
AppendOption (
  IN OUT UINT8  **Cursor,
  IN     UINTN  OptLen
  )
{
  *Cursor += OptLen;
}

// GOOD: option-length fixup modeled on Dhcp6AppendIaOption (`Dhcp6Utility.c:946`).
// A prior option append taints the cursor; the final `Cursor - (UINT8 *)Len - 2`
// is a pointer difference, which the underflow sink excludes, so no alert.
UINT16
Dhcp6AppendIaOptionLenFixup_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS  Status;
  NET_BUF     *Pdu;
  UINT8       *Option;
  UINT8       Buffer[512];
  UINT8       *Cursor;
  UINT16      *Len;
  UINTN       OptLen;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Option = NetbufGetByte (Pdu, 0, NULL);
  if (Option == NULL) {
    return 0;
  }

  OptLen = NTOHS (ReadUnaligned16 ((UINT16 *)(Option + 2)));

  Cursor = Buffer;
  AppendOption (&Cursor, OptLen);  // cursor advanced by a tainted length
  Len     = (UINT16 *)Cursor;      // this option's length slot
  Cursor += 2;                     // DHCP6_SIZE_OF_OPT_LEN
  Cursor += sizeof (UINT32);       // IAID

  return (UINT16)(Cursor - (UINT8 *)Len - 2);
}


// ===== Depleting-subtraction underflows (either operand tainted) =====
//
// unguardedSubtractionUnderflow flags a decrement `Len--`, a compound
// subtraction `Len -= k`, and a binary `a - b` whenever *either* operand is
// attacker-influenced and no dominating guard proves the minuend is at least the
// subtrahend. The tainted scalar below is the R2T DesiredDataTransferLength
// field (industry-standard struct taint via
// IscsiReadyToTransferTaintInheritingContent). Each GOOD adds the dominating
// lower-bound guard that clears the underflow.

// BAD: unguarded decrement of a tainted length — wraps when the length is 0.
UINT32
DepletingDecrement_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len = R2THdr->DesiredDataTransferLength;
  Len--;
  return Len;
}

// GOOD: a dominating `Len > 0` guard clears the decrement underflow.
UINT32
DepletingDecrement_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len = R2THdr->DesiredDataTransferLength;
  if (Len > 0) {
    Len--;
  }

  return Len;
}

// BAD: compound `-=` of a fixed amount from a tainted length, no minimum check.
UINT32
DepletingAssignSubConst_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len   = R2THdr->DesiredDataTransferLength;
  Len  -= 16;
  return Len;
}

// GOOD: the `-=` runs only when `Len >= 16`.
UINT32
DepletingAssignSubConst_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len = R2THdr->DesiredDataTransferLength;
  if (Len >= 16) {
    Len -= 16;
  }

  return Len;
}

// BAD: compound `-=` of one tainted field from another, no `Len >= Amount` check.
UINT32
DepletingAssignSubVar_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;
  UINT32                   Amount;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len    = R2THdr->DesiredDataTransferLength;
  Amount = R2THdr->BufferOffset;
  Len   -= Amount;
  return Len;
}

// GOOD: the `-=` runs only when `Len >= Amount` (non-constant lower-bound guard).
UINT32
DepletingAssignSubVar_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;
  UINT32                   Amount;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len    = R2THdr->DesiredDataTransferLength;
  Amount = R2THdr->BufferOffset;
  if (Len >= Amount) {
    Len -= Amount;
  }

  return Len;
}

// BAD: binary subtraction whose *subtrahend* is the tainted value, so an
// over-large length wraps `512 - Len` below zero.
UINT32
TaintedSubtrahend_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len = R2THdr->DesiredDataTransferLength;
  return (UINT32)(512 - Len);
}

// GOOD: `Len <= 512` guard clears the tainted-subtrahend underflow.
UINT32
TaintedSubtrahend_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS               Status;
  NET_BUF                  *Pdu;
  ISCSI_READY_TO_TRANSFER  *R2THdr;
  UINT32                   Len;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  R2THdr = (ISCSI_READY_TO_TRANSFER *)NetbufGetByte (Pdu, 0, NULL);
  if (R2THdr == NULL) {
    return 0;
  }

  Len = R2THdr->DesiredDataTransferLength;
  if (Len <= 512) {
    return (UINT32)(512 - Len);
  }

  return 0;
}

// ===== CVE-2024-38805: iSCSI login-response data-segment length underflow =====
//
// IScsiProcessLoginRsp reads a login-response PDU via NetbufGetByte and pulls a
// 24-bit data-segment length out of the header with the NTOH24 macro
// (ISCSI_GET_DATASEG_LEN). That length flows through IScsiUpdateTargetAddress
// into IScsiBuildKeyValueList, whose `Len--` decrements the length past the end
// of the data segment and underflows below zero (the sign flip becomes a huge
// UINT32). Unlike the R2T cases above, the tainted length is not a plain UINT32
// field: it is assembled from the `DataSegmentLength[3]` byte array by
// `(b0 << 16) | (b1 << 8) | b2`. Those bitwise ORs would be cut by the
// both-operands-non-constant barrier, so this exercises the
// byte-order-assembly barrier bridge together with the DataSegmentLength
// TaintInheritingContent.

typedef char CHAR8;

typedef struct {
  UINT8   OpCode;
  UINT8   Flags;
  UINT8   VersionMax;
  UINT8   VersionActive;
  UINT8   TotalAHSLength;
  UINT8   DataSegmentLength[3];
  UINT8   Isid[6];
  UINT16  Tsih;
  UINT32  InitiatorTaskTag;
} ISCSI_LOGIN_RESPONSE;

#define NTOH24(src)                    (((src)[0] << 16) | ((src)[1] << 8) | ((src)[2]))
#define ISCSI_GET_DATASEG_LEN(PduHdr)  NTOH24 (((ISCSI_LOGIN_RESPONSE *)(PduHdr))->DataSegmentLength)

// Pre-patch key/value parser: the `if (*Data == '=')` block advances past the
// separator and decrements `Len` with no `Len > 0` check, so an odd data
// segment wraps `Len` below zero.
static
VOID
IScsiBuildKeyValueList_BAD (
  IN CHAR8   *Data,
  IN UINT32  Len
  )
{
  while (Len > 0) {
    while ((Len > 0) && (*Data != '=')) {
      Len--;
      Data++;
    }

    if (*Data == '=') {
      *Data = '\0';
      Data++;
      Len--;              // BAD: unguarded decrement underflows below zero
    } else {
      return;
    }

    Data++;
  }
}

// Post-patch parser (CVE-2024-38805 fix): the separator handling runs only when
// `Len > 0`, so the dominating guard clears the decrement underflow.
static
VOID
IScsiBuildKeyValueList_GOOD (
  IN CHAR8   *Data,
  IN UINT32  Len
  )
{
  while (Len > 0) {
    while ((Len > 0) && (*Data != '=')) {
      Len--;
      Data++;
    }

    if ((Len > 0) && (*Data == '=')) {
      *Data = '\0';
      Data++;
      Len--;              // GOOD: `Len > 0` guard clears the underflow
    } else {
      return;
    }

    Data++;
  }
}

// BAD: the reassembled NTOH24 data-segment length flows across two function
// boundaries into the unguarded decrement.
VOID
IScsiProcessLoginRsp_BAD (
  IN VOID  *Conn
  )
{
  EFI_STATUS            Status;
  NET_BUF               *Pdu;
  ISCSI_LOGIN_RESPONSE  *LoginRsp;
  UINT8                 *DataSeg;
  UINT32                DataSegLen;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return;
  }

  LoginRsp = (ISCSI_LOGIN_RESPONSE *)NetbufGetByte (Pdu, 0, NULL);
  if (LoginRsp == NULL) {
    return;
  }

  DataSegLen = ISCSI_GET_DATASEG_LEN (LoginRsp);
  DataSeg    = NetbufGetByte (Pdu, sizeof (ISCSI_LOGIN_RESPONSE), NULL);
  if (DataSeg == NULL) {
    return;
  }

  IScsiBuildKeyValueList_BAD ((CHAR8 *)DataSeg, DataSegLen);
}

// GOOD: same tainted NTOH24 length, but the patched parser guards the decrement.
VOID
IScsiProcessLoginRsp_GOOD (
  IN VOID  *Conn
  )
{
  EFI_STATUS            Status;
  NET_BUF               *Pdu;
  ISCSI_LOGIN_RESPONSE  *LoginRsp;
  UINT8                 *DataSeg;
  UINT32                DataSegLen;

  Status = IScsiReceivePdu (Conn, &Pdu, NULL, FALSE, FALSE, NULL);
  if (EFI_ERROR (Status)) {
    return;
  }

  LoginRsp = (ISCSI_LOGIN_RESPONSE *)NetbufGetByte (Pdu, 0, NULL);
  if (LoginRsp == NULL) {
    return;
  }

  DataSegLen = ISCSI_GET_DATASEG_LEN (LoginRsp);
  DataSeg    = NetbufGetByte (Pdu, sizeof (ISCSI_LOGIN_RESPONSE), NULL);
  if (DataSeg == NULL) {
    return;
  }

  IScsiBuildKeyValueList_GOOD ((CHAR8 *)DataSeg, DataSegLen);
}
