/**
 * Flow-source model for the NetworkPkg IP6 link-layer receive callback.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * Holds if `f` is a function whose address is registered as the receive
 * callback (`IP6_FRAME_CALLBACK`) of `Ip6ReceiveFrame`.
 *
 * `Ip6ReceiveFrame (CallBack, IpSb)` stores `CallBack` in the MNP receive
 * token and the actual frame delivery happens through an indirect call
 * (`Token->CallBack (Packet, ...)`) in `Ip6OnFrameReceivedDpc`, which the
 * dataflow library cannot resolve. This predicate identifies the callback by
 * the `Ip6ReceiveFrame` registration call instead, recovering the entry point,
 * mirroring how `UdpIoRecvDatagram` callbacks are modeled in `UdpIo.qll`.
 */
predicate isIp6ReceiveFrameCallback(Function f) {
  exists(FunctionCall call |
    call.getTarget().hasName("Ip6ReceiveFrame") and
    f.getAnAccess() = call.getArgument(0)
  )
}

/**
 * The attacker-controlled `NET_BUF *Packet` parameter of an IP6 frame-receive
 * callback (e.g. `Ip6AcceptFrame`).
 *
 * The packet is wrapped from the raw MNP frame bytes
 * (`MnpRxData->PacketData`) by `NetbufFromExt` and delivered to this callback,
 * so its contents are entirely attacker-controlled. The callback's first
 * parameter is the `NET_BUF *`; tainting its pointee (indirection index 1)
 * seeds the `NET_BUF` content, which the `NetLib` content models and the
 * `NetbufGetByte` / `NetbufCopy` helpers then carry into the parsed packet
 * bytes.
 */
class Edk2Ip6ReceiveFrameCallbackSource extends RemoteFlowSource {
  Edk2Ip6ReceiveFrameCallbackSource() {
    exists(Function f |
      isIp6ReceiveFrameCallback(f) and
      this.asParameter(1) = f.getParameter(0)
    )
  }

  override string getSourceType() { result = "packet delivered to an IP6 frame-receive callback" }
}
