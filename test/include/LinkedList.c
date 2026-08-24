#ifndef TEST_INCLUDE_LINKEDLIST_C
#define TEST_INCLUDE_LINKEDLIST_C

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long UINTN;
typedef void VOID;
typedef int BOOLEAN;
typedef UINTN EFI_STATUS;
typedef VOID *EFI_EVENT;

typedef struct LIST_ENTRY {
  struct LIST_ENTRY  *ForwardLink;
  struct LIST_ENTRY  *BackLink;
} LIST_ENTRY;

#define IN
#define OUT
#define OPTIONAL
#define EFIAPI
#define NULL ((VOID *)0)
#define TRUE 1
#define FALSE 0
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 2
#define EFI_BUFFER_TOO_SMALL 5
#define EFI_OUT_OF_RESOURCES 9
#define EFI_ABORTED 10
#define EFI_PROTOCOL_ERROR 13
#define EFI_ERROR(Status) ((Status) != EFI_SUCCESS)

static
VOID
InitializeListHead (
  LIST_ENTRY  *List
  )
{
  List->ForwardLink = List;
  List->BackLink    = List;
}

static
BOOLEAN
IsListEmpty (
  LIST_ENTRY  *List
  )
{
  return List->ForwardLink == List;
}

static
VOID
InsertTailList (
  LIST_ENTRY  *List,
  LIST_ENTRY  *Entry
  )
{
  Entry->ForwardLink          = List;
  Entry->BackLink             = List->BackLink;
  List->BackLink->ForwardLink = Entry;
  List->BackLink              = Entry;
}

static
VOID
RemoveEntryList (
  LIST_ENTRY  *Entry
  )
{
  Entry->BackLink->ForwardLink = Entry->ForwardLink;
  Entry->ForwardLink->BackLink = Entry->BackLink;
}

#endif
