/**
 * Models for the NetworkPkg PXE Base Code DHCPv6 driver
 * (`NetworkPkg/UefiPxeBcDxe/PxeBcDhcp6.c`): the option seeker and the
 * attacker-controlled cached-offer flow source.
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint
private import semmle.code.cpp.security.FlowSources
import lib.MdePkg.Dhcp6

/**
 * `PxeBcDhcp6SeekOption (UINT8 *Buf, UINT32 SeekLen, UINT16 OptType)` walks the
 * option area `Buf` and returns a pointer to the first option of type
 * `OptType`, i.e. a pointer *into* `Buf`.
 *
 * Modeled flow: `arg[*0] -> return[*]` (the pointee bytes of `Buf` reach the
 * pointee bytes of the returned cursor). An explicit model is required because
 * the function returns `Cursor = Buf + (DataLen + 4)` after a parse loop, and
 * the pointer arithmetic on the running cursor is not carried by the body
 * through the dataflow IR. With the model, the attacker-controlled DHCPv6
 * offer option bytes that `Buf` points at stay tainted through the returned
 * `Option` pointer, so the subsequent `((EFI_DHCP6_PACKET_OPTION *)Option)->
 * OpLen` length read is recognised as attacker-controlled (CVE-2023-45235).
 */
class Edk2PxeBcDhcp6SeekOptionTaintFunction extends Function, TaintFunction {
  Edk2PxeBcDhcp6SeekOptionTaintFunction() { this.hasGlobalName("PxeBcDhcp6SeekOption") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}

/**
 * A field of `struct _PXEBC_PRIVATE_DATA` (`NetworkPkg/UefiPxeBcDxe/PxeBcImpl.h`)
 * that holds an attacker-controlled DHCPv6 packet the PXE BC driver later copies
 * options out of:
 *
 *  - `OfferBuffer[]`, the array of cached DHCPv6 offers received from the
 *    network (`Private->OfferBuffer[Index].Dhcp6.Packet.Offer`);
 *  - `Dhcp6Request`, a `CopyMem` of the DHCP6 callback's `Packet` captured at
 *    `Dhcp6SendRequest`. The Request echoes server-supplied options (notably the
 *    Server ID DUID), so its option lengths are attacker-influenced too — which
 *    is why the CVE-2023-45235 fix bounds the `Request->Dhcp6.Option` copy loops
 *    as well.
 *
 * These are exactly the two reads at the top of the vulnerable functions. The
 * declaring type is restricted to `_PXEBC_PRIVATE_DATA` so the names cannot
 * match unrelated fields elsewhere.
 */
class PxeBcPrivateDataDhcp6PacketField extends Field {
  PxeBcPrivateDataDhcp6PacketField() {
    this.getDeclaringType().hasName("_PXEBC_PRIVATE_DATA") and
    this.hasName(["OfferBuffer", "Dhcp6Request"])
  }
}

/** Holds if `f`'s declaring type is the union/struct typedef'd as `name`. */
private predicate declaringTypedefName(Field f, string name) {
  exists(TypedefType t |
    t.hasName(name) and t.getBaseType().getUnderlyingType() = f.getDeclaringType()
  )
}

/**
 * The attacker-controlled cached DHCPv6 packets in the PXE BC private data: a
 * read of `Private->OfferBuffer[]` or `Private->Dhcp6Request`
 * ([[PxeBcPrivateDataDhcp6PacketField]]). The cached `EFI_DHCP6_PACKET` reached
 * through the field (indirection index 1) is the source; the
 * `Dhcp6PacketContentTaintInheritingContent` model then carries the taint down
 * to `Packet->Dhcp6.Option`.
 *
 * A dedicated source is required for CVE-2023-45235. The write and the read are
 * two sequential phases of a *single* `EFI_PXE_BASE_CODE_PROTOCOL.Dhcp()` call,
 * but they live in different call trees that dataflow cannot bridge. The
 * following call-chain sketch shows the disconnected phases in the vulnerable
 * implementation:
 *
 *     EFI_PXE_BASE_CODE_PROTOCOL.Dhcp                  (vtable, PxeBcImpl.c:2214)
 *     +- EfiPxeBcDhcp                                  (PxeBcImpl.c:424)
 *        +- PxeBcDhcp6Sarr (Private, Private->Dhcp6)   (PxeBcImpl.c:460 -> PxeBcDhcp6.c:2306)
 *           |
 *           |  PHASE 1  WRITE (fills the caches)
 *           |  +- Dhcp6->Configure(.., Dhcp6Callback = PxeBcDhcp6CallBack)   (:2347/2363)
 *           |  +- Dhcp6->Start(Dhcp6)                                        (:2381)
 *           |       ~> [Dhcp6Dxe driver, INDIRECT call through the fn pointer]
 *           |            +- PxeBcDhcp6CallBack(.., Packet)                   (:1962)
 *           |                 +- Dhcp6RcvdAdvertise: PxeBcCacheDhcp6Offer    -> Private->OfferBuffer[]
 *           |                 +- Dhcp6SendRequest:  CopyMem(.., Packet, ..)  -> Private->Dhcp6Request (:2073)
 *           |
 *           +- PHASE 2  READ (the sink paths)                               after Start returns
 *              +- PxeBcHandleDhcp6Offer (Private)                           (:2466 -> 1391)
 *                 +- PxeBcRetryDhcp6Binl (Private, Index)                   (:1423/1445/1479 -> 1056)
 *                    +- PxeBcRequestBootService (Private, Index)           (:1104 -> 868)
 *                        Request    = Private->Dhcp6Request                      <- SOURCE (893)
 *                        IndexOffer = &Private->OfferBuffer[Index]...Offer       <- SOURCE (894)
 *                        CopyMem(DiscoverOpt, Option,     OpLen + 4)        <- SINK (938, Server ID)
 *                        CopyMem(DiscoverOpt, RequestOpt, OpLen + 4)        <- SINK (954, option loop)
 *
 * The CVE-2023-45235 fix added length checks at every such copy: the Server ID
 * offer copy (:938), the `Request->Dhcp6.Option` loops in
 * `PxeBcRequestBootService` (:954) and `PxeBcDhcp6Discover` (:2218), and the
 * built-Discover copy into mode data (:2249); all are reported. Dataflow cannot
 * connect PHASE 1 to PHASE 2: (1) `PxeBcDhcp6CallBack` is reached only through
 * an indirect function-pointer dispatch from the separate `Dhcp6Dxe` driver,
 * which the call graph does not resolve; and (2) the packets are handed off
 * through the shared `Private` heap object across the `Dhcp6->Start` boundary —
 * taint is not carried from a store to a struct field in one call tree to a
 * read of it in another. So the cached read in PHASE 2 is modeled as the
 * attacker-controlled entry point here.
 *
 * Both branches anchor on a `_PXEBC_PRIVATE_DATA` field
 * ([[PxeBcPrivateDataDhcp6PacketField]]):
 *
 *  - `Dhcp6Request` is a direct `EFI_DHCP6_PACKET *`; tainting its pointee
 *    reaches `Request->Dhcp6.Option` through the `EFI_DHCP6_PACKET` content
 *    model.
 *  - `OfferBuffer[Index].Dhcp6.Packet.Offer` is read by *address-of a nested
 *    array field*, and CodeQL's content model does not propagate field-path
 *    taint through `&a.b.c.d` (it dies at the `.Dhcp6` sub-access). So the
 *    source is anchored on the `.Offer` / `.Ack` `EFI_DHCP6_PACKET` lvalue whose
 *    access tree contains the `OfferBuffer` field (`offerFa.getAChild+()`),
 *    keeping it tied to `_PXEBC_PRIVATE_DATA.OfferBuffer`.
 */
class Edk2PxeBcCachedDhcp6PacketSource extends RemoteFlowSource {
  Edk2PxeBcCachedDhcp6PacketSource() {
    // Dhcp6Request: direct EFI_DHCP6_PACKET* field of _PXEBC_PRIVATE_DATA.
    exists(FieldAccess fa |
      fa.getTarget().(PxeBcPrivateDataDhcp6PacketField).hasName("Dhcp6Request") and
      this.asIndirectExpr() = fa
    )
    or
    // OfferBuffer: the Offer/Ack EFI_DHCP6_PACKET of the PXEBC_DHCP6_PACKET cache
    // union, read through the _PXEBC_PRIVATE_DATA.OfferBuffer field.
    exists(FieldAccess offerFa, FieldAccess rootFa |
      declaringTypedefName(offerFa.getTarget(), "PXEBC_DHCP6_PACKET") and
      offerFa.getTarget().hasName(["Offer", "Ack"]) and
      rootFa.getTarget().(PxeBcPrivateDataDhcp6PacketField).hasName("OfferBuffer") and
      offerFa.getAChild+() = rootFa and
      this.asIndirectExpr() = offerFa
    )
  }

  override string getSourceType() {
    result = "a cached DHCPv6 packet (PXE BC Private->OfferBuffer/Dhcp6Request)"
  }
}

/**
 * An attacker-controlled DHCPv6 option reached through the `OptList[]` index
 * table of a `PXEBC_DHCP6_PACKET_CACHE` (`NetworkPkg/UefiPxeBcDxe/PxeBcDhcp6.h`):
 * a read of `Cache6->OptList[k]`. Each entry is an `EFI_DHCP6_PACKET_OPTION *`
 * that `PxeBcParseDhcp6Packet` set to `Offer->Dhcp6.Option + Offset`, i.e. a
 * pointer *into* the cached offer packet, so its `->OpLen` / `->Data` are
 * attacker-controlled. The pointee (`asIndirectExpr`, indirection index 1) is
 * the source; the `EFI_DHCP6_PACKET_OPTION` content model then carries taint to
 * `->OpLen` and `->Data`.
 *
 * A dedicated source is required because the table is populated and consumed in
 * different functions across the shared `Private` heap object, which dataflow
 * cannot bridge — the same cross-call-tree hand-off documented for
 * [[Edk2PxeBcCachedDhcp6PacketSource]]. `PxeBcParseDhcp6Packet` writes
 * `Cache6->OptList[PXEBC_DHCP6_IDX_*] = Option` while walking the offer, but
 * the vulnerable read happens later in a separate consumer
 * (`PxeBcCacheDnsServerAddresses` reads
 * `Cache6->OptList[PXEBC_DHCP6_IDX_DNS_SERVER]->OpLen` to size an allocation —
 * CVE-2023-45234). The declaring type is restricted to
 * `PXEBC_DHCP6_PACKET_CACHE` so the DHCP4 cache's `OptList` and the unrelated
 * HTTP-boot `OptList` cannot match.
 */
class Edk2PxeBcDhcp6OptListSource extends RemoteFlowSource {
  Edk2PxeBcDhcp6OptListSource() {
    exists(ArrayExpr ae, FieldAccess fa |
      fa = ae.getArrayBase() and
      declaringTypedefName(fa.getTarget(), "PXEBC_DHCP6_PACKET_CACHE") and
      fa.getTarget().hasName("OptList") and
      this.asIndirectExpr() = ae
    )
  }

  override string getSourceType() {
    result = "a cached DHCPv6 option (PXE BC Cache6->OptList[])"
  }
}
