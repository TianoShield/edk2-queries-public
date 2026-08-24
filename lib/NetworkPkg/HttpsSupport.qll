/**
 * Shared flow-source models for attacker-controlled inputs handled by
 * NetworkPkg/HttpDxe/HttpsSupport.c.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * The attacker-controlled contents of the `Packet` out-parameter at a
 * `TlsCommonReceive(HttpInstance, Packet, Timeout)` call.
 */
class Edk2TlsCommonReceiveSource extends RemoteFlowSource {
  Edk2TlsCommonReceiveSource() {
    exists(FunctionCall call |
      call.getTarget().hasGlobalName("TlsCommonReceive") and
      this.asDefiningArgument() = call.getArgument(1)
    )
  }

  override string getSourceType() { result = "data received by TlsCommonReceive" }
}

/**
 * The attacker-controlled bytes returned by `NetbufAllocSpace` for the header
 * packet that `TlsReceiveOnePdu` immediately passes to `TlsCommonReceive`.
 *
 * This is the alias case where the source reaches the later
 * `TLS_RECORD_HEADER *Header` local through the `NetbufAllocSpace` return value
 * rather than through the `NET_BUF *PduHdr` out-parameter itself.
 */
class Edk2TlsReceiveOnePduAllocSource extends RemoteFlowSource {
  Edk2TlsReceiveOnePduAllocSource() {
    exists(FunctionCall alloc, FunctionCall recv, VariableAccess allocArg, VariableAccess recvArg |
      alloc.getEnclosingFunction() = recv.getEnclosingFunction() and
      recv.getEnclosingFunction().hasGlobalName("TlsReceiveOnePdu") and
      alloc.getTarget().hasGlobalName("NetbufAllocSpace") and
      recv.getTarget().hasGlobalName("TlsCommonReceive") and
      allocArg = alloc.getArgument(0).getFullyConverted().(VariableAccess) and
      recvArg = recv.getArgument(1).getFullyConverted().(VariableAccess) and
      allocArg.getTarget() = recvArg.getTarget() and
      this.asIndirectExpr() = alloc
    )
  }

  override string getSourceType() { result = "data received into a TlsReceiveOnePdu packet buffer" }
}
