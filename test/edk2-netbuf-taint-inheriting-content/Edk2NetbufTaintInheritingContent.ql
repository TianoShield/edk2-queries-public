/**
 * @name NET_BUF TaintInheritingContent flow
 * @description Verifies that the NET_BUF field models in
 *              `lib/NetworkPkg/NetLib.qll` recover taint flow through
 *              NetbufGetByte and NetbufCopy without a query-specific step.
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow
import lib.MdePkg.BaseMemoryLib
import lib.NetworkPkg.NetLib
import Flow::PathGraph

private predicate isProbeSource(DataFlow::Node node) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName(["ProbeNetbufCopy", "ProbeNetbufGetByte"]) and
    fc.getTarget().hasGlobalName(["NetbufCopy", "NetbufGetByte"]) and
    node.asIndirectExpr() = fc.getArgument(0)
  )
}

private predicate isProbeSink(DataFlow::Node node, FunctionCall fc, string sinkLabel) {
  fc.getEnclosingFunction().hasGlobalName("ProbeNetbufCopy") and
  fc.getTarget().hasGlobalName("NetbufCopy") and
  node.asDefiningArgument() = fc.getArgument(3) and
  sinkLabel = "NetbufCopy arg[*3]"
  or
  fc.getEnclosingFunction().hasGlobalName("ProbeNetbufGetByte") and
  fc.getTarget().hasGlobalName("NetbufGetByte") and
  node.asIndirectExpr() = fc and
  sinkLabel = "NetbufGetByte return[*1]"
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { isProbeSource(node) }

  predicate isSink(DataFlow::Node node) { isProbeSink(node, _, _) }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, FunctionCall sinkCall, string sinkLabel
where
  Flow::flowPath(sourceNode, sinkNode) and
  isProbeSink(sinkNode.getNode(), sinkCall, sinkLabel)
select sinkCall, sourceNode, sinkNode, "Taint flows to " + sinkLabel + "."
