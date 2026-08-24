/**
 * Flow-source models for NetworkPkg TCP I/O helpers.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * The attacker-controlled contents received into the `Packet` argument of:
 *
 * `EFI_STATUS TcpIoReceive(TCP_IO *TcpIo, NET_BUF *Packet, BOOLEAN AsyncMode,
 * EFI_EVENT TimeoutEvent)`
 *
 * `TcpIoReceive` fills the NET_BUF passed as argument 1 with bytes received
 * from the remote peer, so the pointed-to packet contents (`arg[*1]`) are
 * attacker-controlled after the call.
 */
class Edk2TcpIoReceiveSource extends RemoteFlowSource {
  Edk2TcpIoReceiveSource() {
    exists(FunctionCall call |
      call.getTarget().hasGlobalName("TcpIoReceive") and
      this.asIndirectExpr() = call.getArgument(1)
    )
  }

  override string getSourceType() { result = "data received by TcpIoReceive" }
}
