/**
 * @name TCP receive flow through TlsCommonReceive, TlsReceiveOnePdu, and HttpsReceive
 * @description Verifies that direct Tcp4/Tcp6 receive-buffer writes in
 *              TlsCommonReceive reach the real downstream TLS helpers,
 *              including RecordHeader parsing, NetbufFromBufList PDU formation,
 *              TlsProcessMessage / BuildResponsePacket inputs, both CopyMem
 *              copies in HttpsReceive, and the final HttpsReceive fragment.
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow
import lib.NetworkPkg.HttpsSupport
import lib.MdePkg.LinkedList
import lib.NetworkPkg.NetBuffer
import lib.NetworkPkg.NetLib
import lib.MdePkg.BaseMemoryLib
import lib.MdePkg.Tls
import lib.MdePkg.Tls1
import Flow::PathGraph

private predicate isRecordHeaderFieldAccess(FieldAccess fa, string functionName, string fieldName) {
  fa.getEnclosingFunction().hasGlobalName(functionName) and
  fa.getTarget().hasName(fieldName) and
  exists(VariableAccess recordHeader |
    recordHeader = fa.getQualifier().getFullyConverted().(VariableAccess) and
    recordHeader.getTarget().hasName("RecordHeader")
  )
}

private predicate isSink(DataFlow::Node node, Expr sinkExpr, string sinkLabel) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName([
        "ProbeTlsCommonReceiveGetByteTcp4OneBlock",
        "ProbeTlsCommonReceiveGetByteTcp6TwoBlock"
      ]) and
    fc.getTarget().hasGlobalName("NetbufGetByte") and
    node.asIndirectExpr() = fc and
    sinkExpr = fc and
    sinkLabel = "TlsCommonReceive -> NetbufGetByte return[*1]"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName([
        "ProbeTlsCommonReceiveCopyTcp4TwoBlock",
        "ProbeTlsCommonReceiveCopyTcp6OneBlock"
      ]) and
    fc.getTarget().hasGlobalName("NetbufCopy") and
    node.asDefiningArgument() = fc.getArgument(3) and
    sinkExpr = fc and
    sinkLabel = "TlsCommonReceive -> NetbufCopy arg[*3]"
  )
  or
  exists(FieldAccess fa |
    isRecordHeaderFieldAccess(fa, "TlsReceiveOnePdu", "ContentType") and
    node.asExpr() = fa and
    sinkExpr = fa and
    sinkLabel = "TlsReceiveOnePdu RecordHeader.ContentType"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName("TlsReceiveOnePdu") and
    fc.getTarget().hasGlobalName("SwapBytes16") and
    node.asExpr() = fc.getArgument(0) and
    sinkExpr = fc and
    sinkLabel = "TlsReceiveOnePdu RecordHeader.Length"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName("TlsReceiveOnePdu") and
    fc.getTarget().hasGlobalName("NetbufFromBufList") and
    node.asIndirectExpr() = fc and
    sinkExpr = fc and
    sinkLabel = "TlsReceiveOnePdu NetbufFromBufList return[*1]"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName([
        "ProbeTlsReceiveOnePduCopyTcp4",
        "ProbeTlsReceiveOnePduCopyTcp6"
      ]) and
    fc.getTarget().hasGlobalName("NetbufCopy") and
    node.asDefiningArgument() = fc.getArgument(3) and
    sinkExpr = fc and
    sinkLabel = "TlsReceiveOnePdu *Pdu -> NetbufCopy arg[*3]"
  )
  or
  exists(FieldAccess fa |
    isRecordHeaderFieldAccess(fa, "HttpsReceive", "ContentType") and
    node.asExpr() = fa and
    sinkExpr = fa and
    sinkLabel = "HttpsReceive RecordHeader.ContentType"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName("HttpsReceive") and
    fc.getTarget().hasGlobalName("NetbufCopy") and
    node.asDefiningArgument() = fc.getArgument(3) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive NetbufCopy arg[*3]"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName("HttpsReceive") and
    fc.getTarget().hasGlobalName("TlsProcessMessage") and
    node.asIndirectExpr() = fc.getArgument(1) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive TlsProcessMessage arg[*1]"
  )
  or
  exists(ExprCall fc, FieldAccess callee |
    fc.getEnclosingFunction().hasGlobalName("HttpsReceive") and
    callee = fc.getExpr().getAChild*().(FieldAccess) and
    callee.getTarget().hasName("BuildResponsePacket") and
    node.asIndirectExpr() = fc.getArgument(1) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive BuildResponsePacket arg[*1]"
  )
  or
  exists(FunctionCall fc, FieldAccess bulk |
    fc.getEnclosingFunction().hasGlobalName("HttpsReceive") and
    fc.getTarget().hasGlobalName("CopyMem") and
    bulk = fc.getArgument(1).getAChild*().(FieldAccess) and
    bulk.getTarget().hasName("Bulk") and
    node.asDefiningArgument() = fc.getArgument(0) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive appdata CopyMem arg[*0]"
  )
  or
  exists(FunctionCall fc, VariableAccess src |
    fc.getEnclosingFunction().hasGlobalName("HttpsReceive") and
    fc.getTarget().hasGlobalName("CopyMem") and
    src = fc.getArgument(1).getAChild*().(VariableAccess) and
    src.getTarget().hasName("BufferOut") and
    node.asDefiningArgument() = fc.getArgument(0) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive alert CopyMem arg[*0]"
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction().hasGlobalName([
        "ProbeHttpsReceiveTcp4",
        "ProbeHttpsReceiveTcp6"
      ]) and
    fc.getTarget().hasGlobalName("CopyMem") and
    node.asDefiningArgument() = fc.getArgument(0) and
    sinkExpr = fc and
    sinkLabel = "HttpsReceive final Fragment.Bulk -> CopyMem arg[*0]"
  )
}

private predicate isTlsBuildResponsePacketTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(ExprCall call, FieldAccess callee |
    callee = call.getExpr().getAChild*().(FieldAccess) and
    callee.getTarget().hasName("BuildResponsePacket") and
    pred.asIndirectExpr() = call.getArgument(1) and
    succ.asDefiningArgument() = call.getArgument(3)
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof Edk2TlsCommonReceiveSource
    or
    node instanceof Edk2TlsReceiveOnePduAllocSource
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    isTlsBuildResponsePacketTaintStep(pred, succ)
  }

  predicate isSink(DataFlow::Node node) { isSink(node, _, _) }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, Expr sinkExpr, string sinkLabel
where
  Flow::flowPath(sourceNode, sinkNode) and
  isSink(sinkNode.getNode(), sinkExpr, sinkLabel)
select sinkExpr, sourceNode, sinkNode, "Taint flows to " + sinkLabel + "."
