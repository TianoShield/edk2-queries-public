/**
 * Models for the NetworkPkg DHCPv6 client driver (`NetworkPkg/Dhcp6Dxe`): the
 * option seeker (`Dhcp6SeekOption`) and the attacker-controlled cached-packet
 * flow sources (`DHCP6_INSTANCE.AdSelect`, `EFI_DHCP6_IA.ReplyPacket`).
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint
private import semmle.code.cpp.security.FlowSources
import lib.MdePkg.Dhcp6

/**
 * `Dhcp6SeekOption (UINT8 *Buf, UINT32 SeekLen, UINT16 OptType)` walks the
 * DHCPv6 option area `Buf` and returns a pointer to the first option of type
 * `OptType`, i.e. a pointer *into* `Buf`.
 *
 * Modeled flow: `arg[*0] -> return[*]` (the pointee bytes of `Buf` reach the
 * pointee bytes of the returned cursor). An explicit model is required because
 * the function returns `Cursor = Buf + (DataLen + 4)` after a parse loop, and
 * the pointer arithmetic on the running cursor is not carried by the body
 * through the dataflow IR. With the model the attacker-controlled option bytes
 * of a cached Advertise/Reply packet stay tainted through the returned
 * `Option` pointer, so the subsequent `((EFI_DHCP6_DUID *)(Option + 2))->Length`
 * read (the Server ID DUID length, CVE-2023-45230) is recognised as
 * attacker-controlled. Mirrors `Edk2PxeBcDhcp6SeekOptionTaintFunction`.
 */
class Edk2Dhcp6SeekOptionTaintFunction extends Function, TaintFunction {
  Edk2Dhcp6SeekOptionTaintFunction() { this.hasGlobalName("Dhcp6SeekOption") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}

/** Holds if `f`'s declaring type is the struct typedef'd as `name`. */
private predicate declaringTypedefName(Field f, string name) {
  exists(TypedefType t |
    t.hasName(name) and t.getBaseType().getUnderlyingType() = f.getDeclaringType()
  )
}

/**
 * A `_DHCP6_INSTANCE.AdSelect` or `EFI_DHCP6_IA.ReplyPacket` field: an
 * `EFI_DHCP6_PACKET *` in which the Dhcp6Dxe driver caches an attacker-supplied
 * DHCPv6 message it later copies Server ID / option bytes out of.
 *
 *  - `AdSelect` (declared in `_DHCP6_INSTANCE`, Dhcp6Impl.h) caches the selected
 *    Advertise: `Dhcp6HandleAdvertiseMsg` does
 *    `Instance->AdSelect = AllocateZeroPool (Packet->Size)` then
 *    `CopyMem (Instance->AdSelect, Packet, Packet->Size)`;
 *  - `ReplyPacket` (declared in `EFI_DHCP6_IA`, MdePkg/Protocol/Dhcp6.h) caches
 *    the latest Reply: `Dhcp6UpdateIaInfo` does the same `AllocateZeroPool` +
 *    `CopyMem` into `Instance->IaCb.Ia->ReplyPacket`.
 */
class Dhcp6InstanceCachedPacketField extends Field {
  Dhcp6InstanceCachedPacketField() {
    this.getDeclaringType().hasName("_DHCP6_INSTANCE") and this.hasName("AdSelect")
    or
    declaringTypedefName(this, "EFI_DHCP6_IA") and this.hasName("ReplyPacket")
  }
}

/**
 * The attacker-controlled cached DHCPv6 packet in the Dhcp6Dxe instance: a read
 * of `Instance->AdSelect` or `Instance->IaCb.Ia->ReplyPacket`
 * ([[Dhcp6InstanceCachedPacketField]]). The cached `EFI_DHCP6_PACKET` reached
 * through the field (indirection index 1) is the source; the
 * `Dhcp6PacketContentTaintInheritingContent` model then carries the taint down
 * to `Packet->Dhcp6.Option`.
 *
 * A dedicated source is required because dataflow cannot bridge the write to
 * the read. The packet is received and cached in the UDP receive call tree
 * (`Dhcp6ReceivePacket -> Dhcp6HandleStateful -> Dhcp6HandleAdvertiseMsg /
 * Dhcp6UpdateIaInfo`, ending in `CopyMem (Instance->AdSelect|ReplyPacket,
 * Packet, ..)`), but the vulnerable read happens later in the message-assembly
 * functions: `Dhcp6SendRequestMsg` reads `Instance->AdSelect`, while
 * `Dhcp6SendDecline/Release/RenewRebindMsg` read `Ia->ReplyPacket`. The
 * hand-off is through the shared `Instance`/`Ia` heap object, across function
 * boundaries and through the `Dhcp6->Start` dispatch, which taint does not
 * cross — the same cross-call store/read gap documented for
 * `Edk2PxeBcCachedDhcp6PacketSource`. The Server ID DUID copied out of the
 * cached packet into the fixed 1024-byte outgoing packet is CVE-2023-45230.
 */
class Edk2Dhcp6CachedPacketSource extends RemoteFlowSource {
  Edk2Dhcp6CachedPacketSource() {
    exists(FieldAccess fa |
      fa.getTarget() instanceof Dhcp6InstanceCachedPacketField and
      this.asIndirectExpr() = fa
    )
  }

  override string getSourceType() {
    result = "a cached DHCPv6 packet (Dhcp6Dxe Instance->AdSelect/Ia->ReplyPacket)"
  }
}
