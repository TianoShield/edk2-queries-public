#include "../include/NetBuffer.c"

UINT8 *
ProbeNetbufGetByte (
  IN NET_BUF  *Nbuf
  )
{
  return NetbufGetByte (Nbuf, 0, (UINT32 *)0);
}

VOID
ProbeNetbufCopy (
  IN NET_BUF  *Nbuf,
  IN UINT8    *Dest
  )
{
  NetbufCopy (Nbuf, 0, 8, Dest);
}
