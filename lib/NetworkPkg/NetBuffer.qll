/**
 * Shared TaintFunction models for functions defined in
 * NetworkPkg/Library/DxeNetLib/NetBuffer.c.
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Models:
 *
 * `UINT8 *NetbufAllocSpace(NET_BUF *Nbuf, UINT32 Len, UINT32 Position)`
 *
 * `NetbufAllocSpace` allocates storage for `Nbuf`, installs that storage into
 * `Nbuf->BlockOp[...]`, and returns a pointer to the allocated bytes. Taint on
 * the packet contents (`arg[*0]`) therefore aliases the bytes reached through
 * the return value (`return[*1]`).
 */
class NetbufAllocSpaceTaintFunction extends Function, TaintFunction {
  NetbufAllocSpaceTaintFunction() { this.hasGlobalName("NetbufAllocSpace") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}

/**
 * Models:
 *
 * `UINT8 *NetbufGetByte(NET_BUF *Nbuf, UINT32 Offset, UINT32 *Index)`
 *
 * `NetbufGetByte` returns a pointer to the `Offset`'th data byte of `Nbuf`
 * (resolving which `NET_BLOCK_OP` fragment holds it). The returned pointer
 * aliases the packet's own storage, so taint on the packet contents
 * (`arg[*0]`) flows to the bytes reached through the return value
 * (`return[*1]`). EDK2 receive paths use it to obtain a pointer to the IPv6
 * extension-header bytes parsed by `Ip6IsExtsValid`.
 */
class NetbufGetByteTaintFunction extends Function, TaintFunction {
  NetbufGetByteTaintFunction() { this.hasGlobalName("NetbufGetByte") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}

/**
 * Models:
 *
 * `NET_BUF *NetbufFromBufList(`
 * `  LIST_ENTRY *BufList, UINT32 HeadSpace, UINT32 HeaderLen,`
 * `  NET_VECTOR_EXT_FREE ExtFree, VOID *Arg OPTIONAL)`
 *
 * `NetbufFromBufList` walks the `BufList`, collects the `NET_BUF` fragments
 * referenced from that list, and returns a new `NET_BUF` assembled from those
 * fragments. Taint on the list contents (`arg[*0]`) therefore flows to the
 * returned packet (`return[*1]`).
 */
class NetbufFromBufListTaintFunction extends Function, TaintFunction {
  NetbufFromBufListTaintFunction() { this.hasGlobalName("NetbufFromBufList") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}

/** Gets `e` with any leading conversions (e.g. `(UINT8 *)`) stripped. */
private Expr stripConversions(Expr e) {
  result = e and not e instanceof Conversion
  or
  result = stripConversions(e.(Conversion).getExpr())
}

/**
 * Gets the address-of expression that the `Dest` argument of a `NetbufCopy`
 * call writes through, whether the destination is `&Obj->Field` passed
 * directly or via a local alias:
 *
 *     Head = &Packet->Dhcp6.Header;
 *     NetbufCopy (Udp6Wrap, 0, Len, (UINT8 *)Head);
 */
private AddressOfExpr netbufCopyDestAddressOf(FunctionCall call) {
  call.getTarget().hasGlobalName("NetbufCopy") and
  exists(Expr dest | dest = stripConversions(call.getArgument(3)) |
    result = dest
    or
    result = dest.(VariableAccess).getTarget().(LocalScopeVariable).getAnAssignedValue()
  )
}

/** Gets the outermost (root) object accessed by the field chain `fa`. */
private Expr fieldChainRoot(FieldAccess fa) {
  result = fa.getQualifier+() and not result instanceof FieldAccess
}

/**
 * Holds if taint flows from the received `NET_BUF` flattened by a `NetbufCopy`
 * call (`arg[*0]`) to the content of the destination object addressed by its
 * `Dest` argument (`arg[3]`).
 *
 * `NetbufCopy (Nbuf, Offset, Len, Dest)` copies the packet bytes of `Nbuf` into
 * `Dest`. EDK2 receive paths allocate a packet struct and pass the address of
 * one of its fields as `Dest`, e.g. in `Dhcp6ReceivePacket`:
 *
 *     Head           = &Packet->Dhcp6.Header;
 *     Packet->Length = NetbufCopy (Udp6Wrap, 0, Len, (UINT8 *)Head);
 *
 * so the whole `*Packet` ends up holding attacker-controlled bytes. The
 * dataflow library does not connect the through-pointer write of `*Head` back
 * to `Packet` across the `&Packet->...` alias, so this step taints the
 * addressed object's content directly. A per-struct TaintInheritingContent
 * model (e.g. `Dhcp6PacketContentTaintInheritingContent`) then carries the
 * taint into the fields the driver parses.
 */
predicate netbufCopyDestObjectStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(FunctionCall call, AddressOfExpr ao |
    ao = netbufCopyDestAddressOf(call) and
    node1.asIndirectExpr() = call.getArgument(0) and
    node2.asIndirectExpr() = fieldChainRoot(ao.getOperand().(FieldAccess))
  )
}
