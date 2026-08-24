/**
 * Flow-source models for NetworkPkg UDP I/O callbacks.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * Holds if `f` is a function whose address is passed as the callback argument
 * to `UdpIoRecvDatagram`.
 */
predicate isUdpIoRecvDatagramCallback(Function f) {
  exists(FunctionCall call |
    call.getTarget().hasName("UdpIoRecvDatagram") and
    f.getAnAccess() = call.getArgument(1)
  )
}

/**
 * The attacker-controlled contents of the packet and endpoint parameters of a
 * `UdpIoRecvDatagram` callback.
 */
class Edk2UdpIoCallbackSource extends RemoteFlowSource {
  Edk2UdpIoCallbackSource() {
    exists(Function f, Parameter p |
      isUdpIoRecvDatagramCallback(f) and
      p = f.getParameter([0, 1]) and
      this.asParameter(1) = p
    )
  }

  override string getSourceType() { result = "data received from a UdpIoRecvDatagram callback" }
}
