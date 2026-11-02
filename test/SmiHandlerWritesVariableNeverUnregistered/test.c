// Test cases for SmiHandlerWritesVariableNeverUnregistered.ql.
//
// The query finds SMI handlers that can reach a UEFI variable write and are
// never unregistered. `*_BAD` functions register such handlers (the
// UserAuthFeaturePkg password SMI before 23ca68c23d and an MM variant);
// `*_GOOD` functions unregister the handler at ExitBootServices, let it
// unregister itself, or register a handler that writes no variables.

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long   UINTN;
typedef UINTN           EFI_STATUS;
typedef unsigned short  CHAR16;
typedef void            VOID;
typedef VOID            *EFI_HANDLE;

#define NULL  ((VOID *)0)

typedef struct {
  UINT32    Data1;
  UINT16    Data2;
  UINT16    Data3;
  UINT8     Data4[8];
} EFI_GUID;

typedef EFI_STATUS (*EFI_SMM_HANDLER_ENTRY_POINT2)(
  EFI_HANDLE  DispatchHandle,
  const VOID  *Context,
  VOID        *CommBuffer,
  UINTN       *CommBufferSize
  );

typedef EFI_STATUS (*EFI_SMM_INTERRUPT_REGISTER)(
  EFI_SMM_HANDLER_ENTRY_POINT2  Handler,
  const EFI_GUID                *HandlerType,
  EFI_HANDLE                    *DispatchHandle
  );

typedef EFI_STATUS (*EFI_SMM_INTERRUPT_UNREGISTER)(
  EFI_HANDLE  DispatchHandle
  );

typedef struct _EFI_SMM_SYSTEM_TABLE2 {
  EFI_SMM_INTERRUPT_REGISTER      SmiHandlerRegister;
  EFI_SMM_INTERRUPT_UNREGISTER    SmiHandlerUnRegister;
} EFI_SMM_SYSTEM_TABLE2;

typedef struct _EFI_MM_SYSTEM_TABLE {
  EFI_SMM_INTERRUPT_REGISTER      MmiHandlerRegister;
  EFI_SMM_INTERRUPT_UNREGISTER    MmiHandlerUnRegister;
} EFI_MM_SYSTEM_TABLE;

typedef EFI_STATUS (*EFI_SET_VARIABLE)(
  CHAR16    *VariableName,
  EFI_GUID  *VendorGuid,
  UINT32    Attributes,
  UINTN     DataSize,
  VOID      *Data
  );

typedef struct _EFI_SMM_VARIABLE_PROTOCOL {
  VOID                *SmmGetVariable;
  VOID                *SmmGetNextVariableName;
  EFI_SET_VARIABLE    SmmSetVariable;
} EFI_SMM_VARIABLE_PROTOCOL;

EFI_SMM_SYSTEM_TABLE2      *gSmst;
EFI_MM_SYSTEM_TABLE        *gMmst;
EFI_SMM_VARIABLE_PROTOCOL  *mSmmVariable;
EFI_GUID                   gUserAuthenticationGuid;
EFI_GUID                   gPolicyGuid;
EFI_GUID                   gTestPointGuid;

EFI_STATUS
SavePasswordHash (
  VOID  *Hash
  )
{
  return mSmmVariable->SmmSetVariable (L"Password", &gUserAuthenticationGuid, 3, 32, Hash);
}

EFI_STATUS
PasswordHandler (
  EFI_HANDLE  DispatchHandle,
  const VOID  *Context,
  VOID        *CommBuffer,
  UINTN       *CommBufferSize
  )
{
  return SavePasswordHash (CommBuffer);
}

EFI_STATUS
PolicyHandler (
  EFI_HANDLE  DispatchHandle,
  const VOID  *Context,
  VOID        *CommBuffer,
  UINTN       *CommBufferSize
  )
{
  return mSmmVariable->SmmSetVariable (L"Policy", &gPolicyGuid, 3, 1, CommBuffer);
}

EFI_STATUS
OneShotHandler (
  EFI_HANDLE  DispatchHandle,
  const VOID  *Context,
  VOID        *CommBuffer,
  UINTN       *CommBufferSize
  )
{
  gSmst->SmiHandlerUnRegister (DispatchHandle);
  return SavePasswordHash (CommBuffer);
}

EFI_STATUS
TestPointHandler (
  EFI_HANDLE  DispatchHandle,
  const VOID  *Context,
  VOID        *CommBuffer,
  UINTN       *CommBufferSize
  )
{
  *CommBufferSize = 0;
  return 0;
}

//
// ---- BAD ----
//

// PasswordSmmInit before 23ca68c23d: the handle lives in a local and is lost.
EFI_STATUS
PasswordSmmInit_BAD (
  VOID
  )
{
  EFI_HANDLE  SmmHandle;

  SmmHandle = NULL;
  return gSmst->SmiHandlerRegister (PasswordHandler, &gUserAuthenticationGuid, &SmmHandle);
}

// MM services table; the handle is kept in a global that is never unregistered.
EFI_HANDLE  mPolicyHandle;

EFI_STATUS
RegisterPolicy_BAD (
  VOID
  )
{
  return gMmst->MmiHandlerRegister (PolicyHandler, &gPolicyGuid, &mPolicyHandle);
}

//
// ---- GOOD ----
//

// PasswordSmmInit after 23ca68c23d: unregistered from an ExitBootServices notification.
EFI_HANDLE  mSmmHandle;

EFI_STATUS
UaExitBootServices (
  const EFI_GUID  *Protocol,
  VOID            *Interface,
  EFI_HANDLE      Handle
  )
{
  gMmst->MmiHandlerUnRegister (mSmmHandle);
  return 0;
}

EFI_STATUS
PasswordSmmInit_GOOD (
  VOID
  )
{
  return gMmst->MmiHandlerRegister (PasswordHandler, &gUserAuthenticationGuid, &mSmmHandle);
}

// The handler unregisters itself on its first invocation.
EFI_STATUS
RegisterOneShot_GOOD (
  VOID
  )
{
  EFI_HANDLE  Handle;

  return gSmst->SmiHandlerRegister (OneShotHandler, &gUserAuthenticationGuid, &Handle);
}

// Never unregistered, but the handler writes no variables.
EFI_STATUS
RegisterTestPoint_GOOD (
  VOID
  )
{
  EFI_HANDLE  Handle;

  return gSmst->SmiHandlerRegister (TestPointHandler, &gTestPointGuid, &Handle);
}
