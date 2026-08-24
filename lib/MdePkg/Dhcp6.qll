/**
 * Shared TaintInheritingContent models for the `EFI_DHCP6_PACKET` family
 * defined in MdePkg/Include/Protocol/Dhcp6.h.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * The `EFI_DHCP6_PACKET` struct:
 *
 *     typedef struct {
 *       UINT32    Size;
 *       UINT32    Length;
 *       struct {
 *         EFI_DHCP6_HEADER    Header;
 *         UINT8               Option[1];
 *       } Dhcp6;
 *     } EFI_DHCP6_PACKET;
 */
class Dhcp6PacketStruct extends Struct {
  Dhcp6PacketStruct() {
    exists(TypedefType t |
      t.hasName("EFI_DHCP6_PACKET") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * A taint-carrying field of `EFI_DHCP6_PACKET`: the embedded `Dhcp6` message
 * struct, or that struct's `Header` / `Option` members. These cover the bytes
 * copied verbatim from the received datagram. The driver-computed `Size` and
 * `Length` bookkeeping fields are deliberately excluded — they are not raw
 * attacker bytes and are used in their own length arithmetic.
 */
class Dhcp6PacketContentField extends Field {
  Dhcp6PacketContentField() {
    this.hasName("Dhcp6") and this.getDeclaringType() instanceof Dhcp6PacketStruct
    or
    exists(Field msg |
      msg.hasName("Dhcp6") and
      msg.getDeclaringType() instanceof Dhcp6PacketStruct and
      this.getDeclaringType() = msg.getType().getUnderlyingType() and
      this.hasName(["Header", "Option"])
    )
  }
}

/**
 * Models taint-preserving reads of the message-bearing fields of
 * `EFI_DHCP6_PACKET` (see [[Dhcp6PacketContentField]]).
 *
 * If an `EFI_DHCP6_PACKET` (or its embedded `Dhcp6` message struct) holds
 * attacker-controlled bytes, then reads of its `Dhcp6`, `Header`, and `Option`
 * members are tainted too. This carries the whole-packet taint introduced at
 * the receive site (where the datagram is flattened into the packet buffer)
 * down through `Packet->Dhcp6.Option` into the option area parsed by the DHCP6
 * driver. Both the field value and the pointee reached through it inherit the
 * taint (`Option` is an array that decays to a pointer into the buffer).
 */
class Dhcp6PacketContentTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  Dhcp6PacketContentTaintInheritingContent() {
    this.getField() instanceof Dhcp6PacketContentField and
    this.getIndirectionIndex() = [1, 2]
  }
}

/**
 * The `EFI_DHCP6_PACKET_OPTION` struct, the on-wire TLV that overlays the
 * option area of an `EFI_DHCP6_PACKET`:
 *
 *     typedef struct {
 *       UINT16    OpCode;
 *       UINT16    OpLen;     ///< length of Data, network byte order
 *       UINT8     Data[1];
 *     } EFI_DHCP6_PACKET_OPTION;
 */
class Dhcp6PacketOptionStruct extends Struct {
  Dhcp6PacketOptionStruct() {
    exists(TypedefType t |
      t.hasName("EFI_DHCP6_PACKET_OPTION") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * Models taint-preserving reads of every field of `EFI_DHCP6_PACKET_OPTION`
 * (`OpCode`, `OpLen`, `Data`).
 *
 * When an option pointer is cast over attacker-controlled DHCPv6 option bytes
 * (e.g. `((EFI_DHCP6_PACKET_OPTION *)Option)->OpLen` where `Option` is a cursor
 * returned by `PxeBcDhcp6SeekOption` into a received offer), reading the TLV's
 * `OpLen` length yields attacker-controlled taint. Both the field value and the
 * pointee reached through it inherit the taint (`Data` decays to a pointer into
 * the option payload).
 */
class Dhcp6PacketOptionTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  Dhcp6PacketOptionTaintInheritingContent() {
    this.getField().getDeclaringType() instanceof Dhcp6PacketOptionStruct and
    this.getIndirectionIndex() = [1, 2]
  }
}

/**
 * The `EFI_DHCP6_DUID` struct (MdePkg/Include/Protocol/Dhcp6.h):
 *
 *     typedef struct {
 *       UINT16    Length;    ///< length of the DUID in octets, network byte order
 *       UINT8     Duid[1];   ///< the DUID octets
 *     } EFI_DHCP6_DUID;
 *
 * A DUID is carried inside a DHCPv6 Server ID / Client ID option; the driver
 * casts an option cursor to `EFI_DHCP6_DUID *` to read its `Length` and `Duid`.
 */
class Dhcp6DuidStruct extends Struct {
  Dhcp6DuidStruct() {
    exists(TypedefType t |
      t.hasName("EFI_DHCP6_DUID") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * Models taint-preserving reads of every field of `EFI_DHCP6_DUID`
 * (`Length`, `Duid`).
 *
 * When a DUID pointer is cast over attacker-controlled DHCPv6 option bytes
 * (`ServerId = (EFI_DHCP6_DUID *)(Dhcp6SeekOption (..) + 2)` in the Dhcp6Dxe
 * message-assembly functions), reading the DUID's `Length` yields
 * attacker-controlled taint. That length is the copy size passed to
 * `Dhcp6AppendOption`, whose `CopyMem (Buf, Data, NTOHS (OptLen))` overflows
 * the fixed outgoing packet (CVE-2023-45230). Both the field value and the
 * pointee reached through it inherit the taint (`Duid` decays to a pointer into
 * the option payload).
 */
class Dhcp6DuidTaintInheritingContent extends TaintInheritingContent, DataFlow::FieldContent {
  Dhcp6DuidTaintInheritingContent() {
    this.getField().getDeclaringType() instanceof Dhcp6DuidStruct and
    this.getIndirectionIndex() = [1, 2]
  }
}
