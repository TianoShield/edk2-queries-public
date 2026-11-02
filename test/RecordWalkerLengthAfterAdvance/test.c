// Test cases for RecordWalkerLengthAfterAdvance.ql.
//
// The query finds record walkers that move the cursor to the next record and
// only then subtract the record length through the moved cursor, so the
// remaining-length counter is reduced by the next record's length.
// `*_BAD` functions reproduce the MinPlatformPkg TestPointCheckLib MADT walker
// (fixed by 3f89df4b1d) and DMAR walkers (fixed by 871ce778eb) and variants;
// `*_GOOD` functions subtract before advancing, or keep the length elsewhere.

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef long            INTN;
typedef unsigned long   UINTN;
typedef void            VOID;

typedef struct {
  UINT32    Signature;
  UINT32    Length;
} TABLE_HEADER;

typedef struct {
  UINT8    Type;
  UINT8    Length;
} APIC_STRUCT_HEADER;

typedef struct {
  UINT16    Type;
  UINT16    Length;
} DMAR_STRUCT_HEADER;

VOID  Dump (UINT16 Type);

//
// ---- BAD: subtraction reads the length through the advanced cursor ----
//

// DumpAcpiMadt before 3f89df4b1d.
VOID
DumpMadt_BAD (
  TABLE_HEADER  *Madt
  )
{
  APIC_STRUCT_HEADER  *ApicStructHeader;
  INTN                MadtLen;

  MadtLen          = Madt->Length - sizeof (TABLE_HEADER);
  ApicStructHeader = (APIC_STRUCT_HEADER *)(Madt + 1);
  while (MadtLen > 0) {
    Dump (ApicStructHeader->Type);
    ApicStructHeader = (APIC_STRUCT_HEADER *)((UINT8 *)ApicStructHeader + ApicStructHeader->Length);
    MadtLen         -= ApicStructHeader->Length;
  }
}

// Unsigned counter, `x = x - len` form, `for` loop, DMAR sub-tables.
VOID
WalkDmar_BAD (
  TABLE_HEADER  *Dmar
  )
{
  DMAR_STRUCT_HEADER  *Entry;
  UINTN               Remaining;

  for (Remaining = Dmar->Length - sizeof (TABLE_HEADER), Entry = (DMAR_STRUCT_HEADER *)(Dmar + 1);
       Remaining > 0;)
  {
    Dump (Entry->Type);
    Entry     = (DMAR_STRUCT_HEADER *)((UINT8 *)Entry + Entry->Length);
    Remaining = Remaining - Entry->Length;
  }
}

// Advance through integer arithmetic and an explicit cast on the subtraction.
VOID
WalkIntegerAdvance_BAD (
  TABLE_HEADER  *Table
  )
{
  APIC_STRUCT_HEADER  *Cursor;
  INTN                Left;

  Left   = Table->Length - sizeof (TABLE_HEADER);
  Cursor = (APIC_STRUCT_HEADER *)(Table + 1);
  while (Left > 0) {
    Cursor = (APIC_STRUCT_HEADER *)((UINTN)Cursor + Cursor->Length);
    Left  -= (INTN)Cursor->Length;
    Dump (Cursor->Type);
  }
}

//
// ---- GOOD: the counter is reduced by the length of the record consumed ----
//

// DumpAcpiMadt after 3f89df4b1d: subtract, then advance.
VOID
DumpMadt_GOOD (
  TABLE_HEADER  *Madt
  )
{
  APIC_STRUCT_HEADER  *ApicStructHeader;
  INTN                MadtLen;

  MadtLen          = Madt->Length - sizeof (TABLE_HEADER);
  ApicStructHeader = (APIC_STRUCT_HEADER *)(Madt + 1);
  while (MadtLen > 0) {
    Dump (ApicStructHeader->Type);
    MadtLen         -= ApicStructHeader->Length;
    ApicStructHeader = (APIC_STRUCT_HEADER *)((UINT8 *)ApicStructHeader + ApicStructHeader->Length);
  }
}

// The record length is saved before the cursor moves.
VOID
WalkSavedLength_GOOD (
  TABLE_HEADER  *Dmar
  )
{
  DMAR_STRUCT_HEADER  *Entry;
  INTN                Remaining;
  UINT16              RecordLength;

  Remaining = Dmar->Length - sizeof (TABLE_HEADER);
  Entry     = (DMAR_STRUCT_HEADER *)(Dmar + 1);
  while (Remaining >= (INTN)sizeof (DMAR_STRUCT_HEADER)) {
    RecordLength = Entry->Length;
    Entry        = (DMAR_STRUCT_HEADER *)((UINT8 *)Entry + RecordLength);
    Remaining   -= RecordLength;
  }
}

// Offset-based walker: the cursor is recomputed from the base each iteration.
VOID
WalkOffset_GOOD (
  TABLE_HEADER  *Table
  )
{
  DMAR_STRUCT_HEADER  *Entry;
  UINTN               Offset;
  UINTN               Left;

  Offset = sizeof (TABLE_HEADER);
  Left   = Table->Length - Offset;
  while (Left > 0) {
    Entry   = (DMAR_STRUCT_HEADER *)((UINT8 *)Table + Offset);
    Offset += Entry->Length;
    Left   -= Entry->Length;
  }
}
