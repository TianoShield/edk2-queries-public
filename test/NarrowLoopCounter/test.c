// Test cases for NarrowLoopCounter.ql.
//
// The query finds loops whose counter type is narrower than the bound it is
// compared with, where the bound can exceed the counter's range. `*_BAD`
// functions reproduce IntelSiliconPkg SmmAccess Close() (UINT8 Index against
// the UINTN NumberRegions copied from the SMRAM HOB, fixed by 62c5bac402) and
// variants; `*_GOOD` functions widen the counter, use a narrow or constant
// bound, or bound the count first.

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long   UINTN;
typedef void            VOID;

#define MAX_UINT16  ((UINT16)0xFFFF)

VOID  DebugAssert (const char *FileName, UINTN LineNumber, const char *Description);

#define ASSERT(Expression)                                    \
  do {                                                        \
    if (!(Expression)) {                                      \
      DebugAssert (__FILE__, __LINE__, #Expression);          \
    }                                                         \
  } while (0)

typedef struct {
  UINTN    NumberRegions;
  UINT8    SmallCount;
  UINT8    SmramDesc[64];
} SMM_ACCESS_PRIVATE_DATA;

typedef struct {
  UINT32    Count;
} REGION_TABLE;

SMM_ACCESS_PRIVATE_DATA  mSmmAccess;

VOID  CloseRegion (UINTN Index);

//
// ---- BAD: the counter wraps before reaching a wider, unbounded count ----
//

// SmmAccessDriver.c Close() before 62c5bac402.
VOID
Close_BAD (
  VOID
  )
{
  UINT8  Index;

  for (Index = 0; Index < mSmmAccess.NumberRegions; Index++) {
    CloseRegion (Index);
  }
}

// UINT16 counter, while loop, `<=`, bound through a pointer.
VOID
WalkTable_BAD (
  REGION_TABLE  *Table
  )
{
  UINT16  Index;

  Index = 0;
  while (Index <= Table->Count) {
    CloseRegion (Index);
    Index++;
  }
}

// `!=` test and `+= 1` update against a parameter.
VOID
CountTo_BAD (
  UINTN  Count
  )
{
  UINT8  Index;

  for (Index = 0; Index != Count; Index += 1) {
    CloseRegion (Index);
  }
}

//
// ---- GOOD ----
//

// SmmAccessDriver.c Close() after 62c5bac402.
VOID
Close_GOOD (
  VOID
  )
{
  UINTN  Index;

  for (Index = 0; Index < mSmmAccess.NumberRegions; Index++) {
    CloseRegion (Index);
  }
}

// The bound is no wider than the counter.
VOID
NarrowBound_GOOD (
  VOID
  )
{
  UINT8  Index;

  for (Index = 0; Index < mSmmAccess.SmallCount; Index++) {
    CloseRegion (Index);
  }
}

// Constant bound within range.
VOID
ConstantBound_GOOD (
  VOID
  )
{
  UINT8  Index;

  for (Index = 0; Index < sizeof (mSmmAccess.SmramDesc); Index++) {
    CloseRegion (Index);
  }
}

// The count is rejected above the counter's range before the loop.
VOID
GuardedCount_GOOD (
  UINTN  Count
  )
{
  UINT8  Index;

  if (Count > 200) {
    return;
  }

  for (Index = 0; Index < Count; Index++) {
    CloseRegion (Index);
  }
}

// MtrrLib style: the count's range is asserted against the counter's maximum.
VOID
AssertedCount_GOOD (
  UINT32  VertexCount
  )
{
  UINT16  Start;

  ASSERT (VertexCount < MAX_UINT16);
  for (Start = 0; Start < VertexCount; Start++) {
    CloseRegion (Start);
  }
}
