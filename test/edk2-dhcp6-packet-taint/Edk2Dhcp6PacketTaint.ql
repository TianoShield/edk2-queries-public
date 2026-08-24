/**
 * @name EFI_DHCP6_PACKET receive-path taint
 * @description Verifies that the EFI_DHCP6_PACKET content models in
 *              lib/MdePkg/Dhcp6.qll, together with the netbufCopyDestObjectStep
 *              from lib/NetworkPkg/NetBuffer.qll, recover taint from a received
 *              NET_BUF into the parsed option area, across the
 *              `&Packet->Dhcp6.Header` NetbufCopy destination alias.
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow
import lib.MdePkg.Dhcp6
import lib.NetworkPkg.NetBuffer
import Flow::PathGraph

private predicate isProbeSource(DataFlow::Node node) {
  exists(FunctionCall fc |
    fc.getTarget().hasGlobalName("NetbufCopy") and
    node.asIndirectExpr() = fc.getArgument(0)
  )
}

private predicate isProbeSink(DataFlow::Node node, FieldAccess fa) {
  fa.getTarget().hasName("Option") and
  fa.getQualifier().(FieldAccess).getTarget().hasName("Dhcp6") and
  node.asIndirectExpr() = fa
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { isProbeSource(node) }

  predicate isSink(DataFlow::Node node) { isProbeSink(node, _) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    netbufCopyDestObjectStep(n1, n2)
  }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink, FieldAccess fa
where Flow::flowPath(source, sink) and isProbeSink(sink.getNode(), fa)
select fa, source, sink, "Taint flows from received NET_BUF to Packet->Dhcp6.Option."
