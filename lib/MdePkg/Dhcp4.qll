/**
 * Shared TaintInheritingContent models for the `EFI_DHCP4_PACKET` /
 * `EFI_DHCP4_HEADER` family defined in MdePkg/Include/Protocol/Dhcp4.h.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

/**
 * The `EFI_DHCP4_PACKET` struct:
 *
 *     typedef struct {
 *       UINT32    Size;
 *       UINT32    Length;
 *       struct {
 *         EFI_DHCP4_HEADER    Header;
 *         UINT32              Magik;
 *         UINT8               Option[1];
 *       } Dhcp4;
 *     } EFI_DHCP4_PACKET;
 */
class Dhcp4PacketStruct extends Struct {
  Dhcp4PacketStruct() {
    exists(TypedefType t |
      t.hasName("EFI_DHCP4_PACKET") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * The `EFI_DHCP4_HEADER` struct: the fixed BOOTP/DHCP header copied verbatim
 * from the received datagram.
 */
class Dhcp4HeaderStruct extends Struct {
  Dhcp4HeaderStruct() {
    exists(TypedefType t |
      t.hasName("EFI_DHCP4_HEADER") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

/**
 * A taint-carrying field of `EFI_DHCP4_PACKET`: the embedded `Dhcp4` message
 * struct, or that struct's `Header` / `Magik` / `Option` members. These cover
 * the bytes copied verbatim from the received datagram. The driver-computed
 * `Size` and `Length` bookkeeping fields are deliberately excluded — they are
 * not raw attacker bytes and are used in their own length arithmetic.
 */
class Dhcp4PacketContentField extends Field {
  Dhcp4PacketContentField() {
    this.hasName("Dhcp4") and this.getDeclaringType() instanceof Dhcp4PacketStruct
    or
    exists(Field msg |
      msg.hasName("Dhcp4") and
      msg.getDeclaringType() instanceof Dhcp4PacketStruct and
      this.getDeclaringType() = msg.getType().getUnderlyingType() and
      this.hasName(["Header", "Magik", "Option"])
    )
  }
}

/**
 * Any field of `EFI_DHCP4_HEADER`. Every field of the header is a raw byte (or
 * group of bytes) lifted straight from the received packet, so all of them
 * inherit the whole-packet taint.
 */
class Dhcp4HeaderContentField extends Field {
  Dhcp4HeaderContentField() { this.getDeclaringType() instanceof Dhcp4HeaderStruct }
}

/**
 * Models taint-preserving reads of the message-bearing fields of
 * `EFI_DHCP4_PACKET` (see [[Dhcp4PacketContentField]]) and of every field of
 * `EFI_DHCP4_HEADER` (see [[Dhcp4HeaderContentField]]).
 *
 * If an `EFI_DHCP4_PACKET` (or its embedded header) holds attacker-controlled
 * bytes, then reads of its content members are tainted too. This carries the
 * whole-packet taint introduced at the receive site (where the datagram is
 * flattened into the packet buffer by `NetbufCopy`) down through
 * `Packet->Dhcp4.Header` and into scalar fields parsed by the DHCP4 driver.
 * Both the field value and the pointee reached through it inherit the taint
 * (`Option` decays to a pointer into the buffer).
 */
class Dhcp4ContentTaintInheritingContent extends TaintInheritingContent, DataFlow::FieldContent {
  Dhcp4ContentTaintInheritingContent() {
    (
      this.getField() instanceof Dhcp4PacketContentField
      or
      this.getField() instanceof Dhcp4HeaderContentField
    ) and
    this.getIndirectionIndex() = [1, 2]
  }
}
