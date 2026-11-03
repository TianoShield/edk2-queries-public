// Test cases for UnvalidatedDataPublishedToHob.ql.
//
// The query tracks UEFI variable contents (`Edk2UefiVariableDataSource`) into
// the data copied into a GUID HOB, reporting sources whose contents are never
// tested by a branch condition. `*_BAD` functions reproduce MinPlatformPkg
// BuildMemoryTypeInformation before 87c40ac89b and variants; `*_GOOD`
// functions validate the contents first, or publish constant data.

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long   UINTN;
typedef UINTN           EFI_STATUS;
typedef unsigned short  CHAR16;
typedef void            VOID;

#define NULL  ((VOID *)0)
#define EFI_COMPROMISED_DATA  0x8000000000000021
#define EFI_ERROR(StatusCode)  (((long)(StatusCode)) < 0)

typedef struct {
  UINT32    Data1;
  UINT16    Data2;
  UINT16    Data3;
  UINT8     Data4[8];
} EFI_GUID;

typedef enum {
  EfiReservedMemoryType,
  EfiRuntimeServicesCode,
  EfiRuntimeServicesData,
  EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct {
  UINT32    Type;
  UINT32    NumberOfPages;
} EFI_MEMORY_TYPE_INFORMATION;

typedef struct _EFI_PEI_READ_ONLY_VARIABLE2_PPI EFI_PEI_READ_ONLY_VARIABLE2_PPI;

typedef EFI_STATUS (*EFI_PEI_GET_VARIABLE2)(
  const EFI_PEI_READ_ONLY_VARIABLE2_PPI  *This,
  const CHAR16                           *VariableName,
  const EFI_GUID                         *VariableGuid,
  UINT32                                 *Attributes,
  UINTN                                  *DataSize,
  VOID                                   *Data
  );

struct _EFI_PEI_READ_ONLY_VARIABLE2_PPI {
  EFI_PEI_GET_VARIABLE2    GetVariable;
  VOID                     *NextVariableName;
};

// The PPI implementation (MdeModulePkg Variable/Pei).
EFI_STATUS
PeiGetVariable (
  const EFI_PEI_READ_ONLY_VARIABLE2_PPI  *This,
  const CHAR16                           *VariableName,
  const EFI_GUID                         *VariableGuid,
  UINT32                                 *Attributes,
  UINTN                                  *DataSize,
  VOID                                   *Data
  );

typedef EFI_STATUS (*EFI_GET_VARIABLE)(
  CHAR16    *VariableName,
  EFI_GUID  *VendorGuid,
  UINT32    *Attributes,
  UINTN     *DataSize,
  VOID      *Data
  );

// Anonymous struct behind a typedef, as in UefiSpec.h.
typedef struct {
  VOID                *GetTime;
  EFI_GET_VARIABLE    GetVariable;
} EFI_RUNTIME_SERVICES;

EFI_RUNTIME_SERVICES  *gRT;
EFI_GUID              gEfiMemoryTypeInformationGuid;
EFI_GUID              gPlatformConfigGuid;

// Variable names (L"..." needs -fshort-wchar to match CHAR16).
CHAR16  mMemoryTypeInformationName[] = { 'M', 'T', 'I', 0 };
CHAR16  mPlatformConfigName[]        = { 'P', 'C', 0 };

VOID  *BuildGuidDataHob (const EFI_GUID *Guid, VOID *Data, UINTN DataLength);
VOID  *BuildGuidHob (const EFI_GUID *Guid, UINTN DataLength);
VOID  *CopyMem (VOID *DestinationBuffer, const VOID *SourceBuffer, UINTN Length);

EFI_MEMORY_TYPE_INFORMATION  mDefaultMemoryTypeInformation[] = {
  { EfiRuntimeServicesData, 0x20 },
  { EfiMaxMemoryType,       0    }
};

// Dataflow only creates argument positions that some direct call uses. EDK2
// has many six-argument calls; without one here, the PPI call's `Data`
// argument (index 5) would get no output node in this small test.
EFI_STATUS
ReadThroughImplementation (
  VOID   *Buffer,
  UINTN  *Size
  )
{
  return PeiGetVariable (NULL, mPlatformConfigName, &gPlatformConfigGuid, NULL, Size, Buffer);
}

//
// ---- BAD: variable contents copied into a HOB with no content check ----
//

// BuildMemoryTypeInformation before 87c40ac89b.
VOID
BuildMemoryTypeInformation_BAD (
  EFI_PEI_READ_ONLY_VARIABLE2_PPI  *VariableServices
  )
{
  EFI_STATUS                   Status;
  UINTN                        DataSize;
  EFI_MEMORY_TYPE_INFORMATION  MemoryData[EfiMaxMemoryType + 1];

  DataSize = sizeof (MemoryData);
  Status   = VariableServices->GetVariable (
                                 VariableServices,
                                 mMemoryTypeInformationName,
                                 &gEfiMemoryTypeInformationGuid,
                                 NULL,
                                 &DataSize,
                                 &MemoryData
                                 );
  if (EFI_ERROR (Status)) {
    DataSize = sizeof (mDefaultMemoryTypeInformation);
    CopyMem (MemoryData, mDefaultMemoryTypeInformation, DataSize);
  }

  BuildGuidDataHob (&gEfiMemoryTypeInformationGuid, MemoryData, DataSize);
}

// Runtime-services read through a helper, published with the two-step
// BuildGuidHob + CopyMem form.
EFI_STATUS
ReadPlatformConfig (
  UINT8  *Buffer,
  UINTN  *Size
  )
{
  return gRT->GetVariable (mPlatformConfigName, &gPlatformConfigGuid, NULL, Size, Buffer);
}

VOID
PublishPlatformConfig_BAD (
  VOID
  )
{
  UINT8  Config[64];
  UINTN  Size;
  VOID   *Hob;

  Size = sizeof (Config);
  if (EFI_ERROR (ReadPlatformConfig (Config, &Size))) {
    return;
  }

  Hob = BuildGuidHob (&gPlatformConfigGuid, Size);
  if (Hob == NULL) {
    return;
  }

  CopyMem (Hob, Config, Size);
}

//
// ---- GOOD ----
//

// BuildMemoryTypeInformation after 87c40ac89b: the entries are validated and
// the defaults are used when they are not.
VOID
BuildMemoryTypeInformation_GOOD (
  EFI_PEI_READ_ONLY_VARIABLE2_PPI  *VariableServices
  )
{
  EFI_STATUS                   Status;
  UINTN                        DataSize;
  UINTN                        Index;
  EFI_MEMORY_TYPE_INFORMATION  MemoryData[EfiMaxMemoryType + 1];

  DataSize = sizeof (MemoryData);
  Status   = VariableServices->GetVariable (
                                 VariableServices,
                                 mMemoryTypeInformationName,
                                 &gEfiMemoryTypeInformationGuid,
                                 NULL,
                                 &DataSize,
                                 &MemoryData
                                 );
  if (!EFI_ERROR (Status)) {
    if (DataSize % sizeof (EFI_MEMORY_TYPE_INFORMATION) != 0) {
      Status = EFI_COMPROMISED_DATA;
    } else {
      for (Index = 0; Index < ((DataSize / sizeof (EFI_MEMORY_TYPE_INFORMATION)) - 1); Index++) {
        if (MemoryData[Index].Type >= EfiMaxMemoryType) {
          Status = EFI_COMPROMISED_DATA;
        }
      }

      if ((MemoryData[Index].Type != EfiMaxMemoryType) || (MemoryData[Index].NumberOfPages != 0)) {
        Status = EFI_COMPROMISED_DATA;
      }
    }
  }

  if (EFI_ERROR (Status)) {
    DataSize = sizeof (mDefaultMemoryTypeInformation);
    CopyMem (MemoryData, mDefaultMemoryTypeInformation, DataSize);
  }

  BuildGuidDataHob (&gEfiMemoryTypeInformationGuid, MemoryData, DataSize);
}

// Only constant data reaches the HOB; the variable is read for another use.
VOID
PublishDefaults_GOOD (
  EFI_PEI_READ_ONLY_VARIABLE2_PPI  *VariableServices
  )
{
  UINT8  Unused[16];
  UINTN  Size;

  Size = sizeof (Unused);
  VariableServices->GetVariable (VariableServices, mPlatformConfigName, &gPlatformConfigGuid, NULL, &Size, Unused);
  BuildGuidDataHob (
    &gEfiMemoryTypeInformationGuid,
    mDefaultMemoryTypeInformation,
    sizeof (mDefaultMemoryTypeInformation)
    );
}
