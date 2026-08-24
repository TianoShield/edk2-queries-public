#ifndef TEST_INCLUDE_NETBUFFER_C
#define TEST_INCLUDE_NETBUFFER_C

#include "LinkedList.c"

#define ASSERT(Cond)
#define NET_BUF_SIGNATURE 0
#define NET_CHECK_SIGNATURE(PData, Signature)
#define NET_BUF_TAIL 0

typedef struct {
  UINT8   *BlockHead;
  UINT8   *BlockTail;
  UINT8   *Head;
  UINT8   *Tail;
  UINT32  Size;
} NET_BLOCK_OP;

typedef struct {
  UINT32        Signature;
  UINT32        BlockOpNum;
  UINT32        TotalSize;
  LIST_ENTRY    List;
  NET_BLOCK_OP  BlockOp[1];
} NET_BUF;

typedef struct {
  UINT32  Len;
  UINT8   *Bulk;
} NET_FRAGMENT;

typedef
VOID
(EFIAPI *NET_VECTOR_EXT_FREE) (
  IN VOID  *Arg
  );

VOID *
AllocatePool (
  UINTN  AllocationSize
  );

VOID
FreePool (
  VOID  *Buffer
  );

VOID *
CopyMem (
  VOID        *DestinationBuffer,
  const VOID  *SourceBuffer,
  UINTN       Length
  );

UINT8 *
EFIAPI
NetbufGetByte (
  IN  NET_BUF  *Nbuf,
  IN  UINT32   Offset,
  OUT UINT32   *Index OPTIONAL
  )
{
  NET_BLOCK_OP  *BlockOp;
  UINT32        Loop;
  UINT32        Len;

  NET_CHECK_SIGNATURE (Nbuf, NET_BUF_SIGNATURE);

  if (Offset >= Nbuf->TotalSize) {
    return NULL;
  }

  BlockOp = Nbuf->BlockOp;
  Len     = 0;

  for (Loop = 0; Loop < Nbuf->BlockOpNum; Loop++) {
    if (Len + BlockOp[Loop].Size <= Offset) {
      Len += BlockOp[Loop].Size;
      continue;
    }

    if (Index != NULL) {
      *Index = Loop;
    }

    return BlockOp[Loop].Head + (Offset - Len);
  }

  return NULL;
}

UINT32
NetbufCopy (
  IN NET_BUF  *Nbuf,
  IN UINT32   Offset,
  IN UINT32   Len,
  IN UINT8    *Dest
  )
{
  NET_BLOCK_OP  *BlockOp;
  UINT32        Skip;
  UINT32        Left;
  UINT32        Copied;
  UINT32        Index;
  UINT32        Cur;

  NET_CHECK_SIGNATURE (Nbuf, NET_BUF_SIGNATURE);
  ASSERT (Dest);

  if ((Len == 0) || (Nbuf->TotalSize <= Offset)) {
    return 0;
  }

  if (Nbuf->TotalSize - Offset < Len) {
    Len = Nbuf->TotalSize - Offset;
  }

  BlockOp = Nbuf->BlockOp;
  Cur     = 0;

  for (Index = 0; Index < Nbuf->BlockOpNum; Index++) {
    if (BlockOp[Index].Size == 0) {
      continue;
    }

    if (Offset < Cur + BlockOp[Index].Size) {
      break;
    }

    Cur += BlockOp[Index].Size;
  }

  Skip = Offset - Cur;
  Left = BlockOp[Index].Size - Skip;

  if (Len <= Left) {
    CopyMem (Dest, BlockOp[Index].Head + Skip, Len);
    return Len;
  }

  CopyMem (Dest, BlockOp[Index].Head + Skip, Left);

  Dest   += Left;
  Len    -= Left;
  Copied = Left;

  Index++;

  for ( ; Index < Nbuf->BlockOpNum; Index++) {
    if (Len > BlockOp[Index].Size) {
      Len    -= BlockOp[Index].Size;
      Copied += BlockOp[Index].Size;

      CopyMem (Dest, BlockOp[Index].Head, BlockOp[Index].Size);
      Dest += BlockOp[Index].Size;
    } else {
      Copied += Len;
      CopyMem (Dest, BlockOp[Index].Head, Len);
      break;
    }
  }

  return Copied;
}

static
VOID
InitializeBlockOp (
  NET_BLOCK_OP  *BlockOp,
  UINT8         *Data,
  UINT32        Size
  )
{
  BlockOp->BlockHead = Data;
  BlockOp->BlockTail = Data + Size;
  BlockOp->Head      = Data;
  BlockOp->Tail      = Data + Size;
  BlockOp->Size      = Size;
}

static
NET_BUF *
AllocateNetbufWithBlocks (
  UINT32  BlockCount
  )
{
  NET_BUF  *Nbuf;

  if (BlockCount == 0) {
    BlockCount = 1;
  }

  Nbuf = (NET_BUF *)AllocatePool (sizeof (NET_BUF) + (BlockCount - 1) * sizeof (NET_BLOCK_OP));
  if (Nbuf == NULL) {
    return NULL;
  }

  Nbuf->Signature  = NET_BUF_SIGNATURE;
  Nbuf->BlockOpNum = BlockCount;
  Nbuf->TotalSize  = 0;
  InitializeListHead (&Nbuf->List);
  return Nbuf;
}

static
NET_BUF *
MakeSingleBlockPacket (
  UINT8   *Block0,
  UINT32  Len0
  )
{
  NET_BUF  *Nbuf;

  Nbuf = AllocateNetbufWithBlocks (1);
  if (Nbuf == NULL) {
    return NULL;
  }

  InitializeBlockOp (&Nbuf->BlockOp[0], Block0, Len0);
  Nbuf->TotalSize = Len0;
  return Nbuf;
}

static
NET_BUF *
MakeTwoBlockPacket (
  UINT8   *Block0,
  UINT32  Len0,
  UINT8   *Block1,
  UINT32  Len1
  )
{
  NET_BUF  *Nbuf;

  Nbuf = AllocateNetbufWithBlocks (2);
  if (Nbuf == NULL) {
    return NULL;
  }

  InitializeBlockOp (&Nbuf->BlockOp[0], Block0, Len0);
  InitializeBlockOp (&Nbuf->BlockOp[1], Block1, Len1);
  Nbuf->TotalSize = Len0 + Len1;
  return Nbuf;
}

EFI_STATUS
EFIAPI
NetbufBuildExt (
  IN NET_BUF           *Nbuf,
  IN OUT NET_FRAGMENT  *ExtFragment,
  IN OUT UINT32        *ExtNum
  )
{
  UINT32  Index;
  UINT32  Current;

  Current = 0;

  for (Index = 0; Index < Nbuf->BlockOpNum; Index++) {
    if (Nbuf->BlockOp[Index].Size == 0) {
      continue;
    }

    if (Current < *ExtNum) {
      ExtFragment[Current].Len  = Nbuf->BlockOp[Index].Size;
      ExtFragment[Current].Bulk = Nbuf->BlockOp[Index].Head;
      Current++;
    } else {
      return EFI_BUFFER_TOO_SMALL;
    }
  }

  *ExtNum = Current;
  return EFI_SUCCESS;
}

NET_BUF *
NetbufAlloc (
  UINT32  Len
  )
{
  NET_BUF  *Nbuf;

  Nbuf = AllocateNetbufWithBlocks (1);
  if (Nbuf == NULL) {
    return NULL;
  }

  Nbuf->TotalSize = Len;
  return Nbuf;
}

UINT8 *
NetbufAllocSpace (
  NET_BUF  *Nbuf,
  UINT32   Len,
  UINT32   Position
  )
{
  UINT8  *Data;

  Data = (UINT8 *)AllocatePool (Len == 0 ? 1 : Len);
  if (Data == NULL) {
    return NULL;
  }

  InitializeBlockOp (&Nbuf->BlockOp[0], Data, Len);
  Nbuf->TotalSize = Len;
  return Data;
}

static
NET_BUF *
NetbufFromExt (
  IN NET_FRAGMENT         *ExtFragment,
  IN UINT32               ExtNum,
  IN UINT32               HeadSpace,
  IN UINT32               HeaderLen,
  IN NET_VECTOR_EXT_FREE  ExtFree,
  IN VOID                 *Arg OPTIONAL
  )
{
  NET_BUF  *Nbuf;
  UINT32   Index;

  Nbuf = AllocateNetbufWithBlocks (ExtNum);
  if (Nbuf == NULL) {
    return NULL;
  }

  for (Index = 0; Index < ExtNum; Index++) {
    InitializeBlockOp (&Nbuf->BlockOp[Index], ExtFragment[Index].Bulk, ExtFragment[Index].Len);
    Nbuf->TotalSize += ExtFragment[Index].Len;
  }

  return Nbuf;
}

#define OFFSET_OF(TYPE, Field) ((UINTN)&(((TYPE *)0)->Field))
#define NET_BUF_FROM_LIST_ENTRY(Entry) \
  ((NET_BUF *)((UINT8 *)(Entry) - OFFSET_OF(NET_BUF, List)))

NET_BUF *
NetbufFromBufList (
  IN LIST_ENTRY           *BufList,
  IN UINT32               HeadSpace,
  IN UINT32               HeaderLen,
  IN NET_VECTOR_EXT_FREE  ExtFree,
  IN VOID                 *Arg OPTIONAL
  )
{
  NET_FRAGMENT  *Fragment;
  UINT32        FragmentNum;
  LIST_ENTRY    *Entry;
  NET_BUF       *Nbuf;
  UINT32        Index;
  UINT32        Current;

  FragmentNum = 0;

  for (Entry = BufList->ForwardLink; Entry != BufList; Entry = Entry->ForwardLink) {
    Nbuf = NET_BUF_FROM_LIST_ENTRY (Entry);
    NET_CHECK_SIGNATURE (Nbuf, NET_BUF_SIGNATURE);
    FragmentNum += Nbuf->BlockOpNum;
  }

  Fragment = (NET_FRAGMENT *)AllocatePool (sizeof (NET_FRAGMENT) * FragmentNum);
  if (Fragment == NULL) {
    return NULL;
  }

  Current = 0;

  for (Entry = BufList->ForwardLink; Entry != BufList; Entry = Entry->ForwardLink) {
    Nbuf = NET_BUF_FROM_LIST_ENTRY (Entry);
    NET_CHECK_SIGNATURE (Nbuf, NET_BUF_SIGNATURE);

    for (Index = 0; Index < Nbuf->BlockOpNum; Index++) {
      if (Nbuf->BlockOp[Index].Size != 0) {
        Fragment[Current].Len  = Nbuf->BlockOp[Index].Size;
        Fragment[Current].Bulk = Nbuf->BlockOp[Index].Head;
        Current++;
      }
    }
  }

  Nbuf = NetbufFromExt (Fragment, Current, HeadSpace, HeaderLen, ExtFree, Arg);
  FreePool (Fragment);
  return Nbuf;
}

VOID
NetbufFree (
  NET_BUF  *Nbuf
  )
{
  if (Nbuf != NULL) {
    FreePool (Nbuf);
  }
}

VOID
EFIAPI
FreeNbufList (
  IN VOID  *Arg
  )
{
  LIST_ENTRY  *BufList;
  LIST_ENTRY  *Entry;
  NET_BUF     *Nbuf;

  BufList = (LIST_ENTRY *)Arg;
  if (BufList == NULL) {
    return;
  }

  while (!IsListEmpty (BufList)) {
    Entry = BufList->ForwardLink;
    RemoveEntryList (Entry);
    Nbuf = NET_BUF_FROM_LIST_ENTRY (Entry);
    NetbufFree (Nbuf);
  }

  FreePool (BufList);
}

#endif
