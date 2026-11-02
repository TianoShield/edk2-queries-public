/**
 * @name Unvalidated input published in a HOB
 * @description Data from an untrusted source, such as a UEFI variable read in
 *              PEI, is copied into a GUID HOB without any check of its
 *              contents. Later phases parse HOBs as trusted platform data (for
 *              example by walking an array until a terminator entry), so
 *              malformed contents become out-of-bounds reads there.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id cpp/edk2-unvalidated-data-published-to-hob
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-125
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

/**
 * Holds if `source` is a configured flow source and `sourceType` is its
 * user-facing provenance string.
 */
predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

/**
 * Holds if `node` is the pointed-to data of the argument that `call` copies
 * into a GUID HOB (`isGuidHobDataArgument`).
 */
predicate isHobDataSink(DataFlow::Node node, FunctionCall call) {
  exists(Expr arg | isGuidHobDataArgument(call, arg) and node.asIndirectExpr(1) = arg)
}

/**
 * Tracks source data into branch conditions outside DebugLib assertions, to
 * find sources whose contents are checked somewhere.
 */
module ContentCheckConfig implements DataFlow::ConfigSig {
  /** Holds if `node` is one of the shared attacker flow sources. */
  predicate isSource(DataFlow::Node node) { node instanceof FS::FlowSource }

  /** Holds if `node` is read by a branch condition that is not an assertion. */
  predicate isSink(DataFlow::Node node) {
    exists(GuardCondition g, Expr e |
      e = g.(Expr).getAChild*() and
      // IR guards include any value-producing expression; only one that
      // decides a branch is a check.
      g.controls(_, _) and
      not isInDebugAssertion(e)
    |
      node.asExpr() = e
      or
      // A field read in the condition, as in `MemoryData[Index].Type`: taint on
      // the record does not flow into the field value, so the record that the
      // field is read from counts as checked.
      node.asIndirectExpr() = e.(FieldAccess).getQualifier()
    )
  }
}

module ContentCheckFlow = TaintTracking::Global<ContentCheckConfig>;

/**
 * Holds if the data read at `source` reaches a branch condition, as in the
 * validation loop added for the MemoryTypeInformation variable:
 *
 *     if (MemoryData[Index].Type >= EfiMaxMemoryType) { Status = EFI_COMPROMISED_DATA; }
 *
 * Any content check counts. The query targets data published with no check
 * at all, and does not judge whether a check is sufficient.
 */
predicate isContentChecked(DataFlow::Node source) { ContentCheckFlow::flow(source, _) }

module Config implements DataFlow::ConfigSig {
  /** Holds if `node` is a shared attacker flow source whose contents are never checked. */
  predicate isSource(DataFlow::Node node) {
    node instanceof FS::FlowSource and
    not isContentChecked(node)
  }

  /** Holds if `node` is data copied into a GUID HOB. */
  predicate isSink(DataFlow::Node node) { isHobDataSink(node, _) }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, FunctionCall call
where
  Flow::flowPath(sourceNode, sinkNode) and
  isHobDataSink(sinkNode.getNode(), call)
select call, sourceNode, sinkNode,
  "Data from $@ is published in a GUID HOB by " + call.getTarget().getName() +
    " without any check of its contents.", sourceNode.getNode(),
  any(string sourceType | isSource(sourceNode.getNode(), sourceType))
