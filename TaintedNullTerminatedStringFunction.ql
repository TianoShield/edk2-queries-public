/**
 * @name Tainted remote input flows to string function requiring null termination
 * @description Attacker-controlled remote input flows to a function that
 *              assumes its input is null-terminated (e.g. AsciiStrLen, StrLen,
 *              AsciiStrCpy, AsciiStrCmp, AsciiPrint, etc.). If the buffer is
 *              not properly null-terminated, the function may read or write
 *              out of bounds.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/tainted-null-terminated-string-function-from-udpio-callback
 * @tags security
 *       external/cwe/cwe-170
 *       external/cwe/cwe-125
 *       external/cwe/cwe-20
 */

import cpp
import semmle.code.cpp.commons.NullTermination
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

// Adapted from cpp/ql/src/Security/CWE/CWE-170/ImproperNullTerminationTainted.ql
/**
 * Holds if `sink` is an expression that must be null-terminated and is passed
 * through variable access `va`.
 */
predicate isSink(DataFlow::Node sink, VariableAccess va) {
  va = sink.asIndirectExpr() and
  variableMustBeNullTerminated(va) and
  // Exclude bounded strlen functions (StrnLenS, StrnSizeS and their Ascii
  // variants).  These accept a MaxSize parameter that caps how far they scan,
  // so passing untrusted data is safe — they are specifically designed for
  // sizing incoming buffers of known capacity.
  not exists(FunctionCall fc |
    fc.getAnArgument() = va and
    fc.getTarget() instanceof Edk2StrnLenSFunction
  )
}

/**
 * Holds if `source` is a configured flow source and `sourceType` is its
 * user-facing provenance string.
 */
predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

module Config implements DataFlow::ConfigSig {
  /** Holds if `node` is one of the configured flow sources. */
  predicate isSource(DataFlow::Node node) { isSource(node, _) }

  // Adapted from the assignment form of mayAddNullTerminator in NullTermination.qll.
  // Fires when a zero byte has been explicitly written to the same variable
  // accessed at this node (buf[i] = '\0' or *buf = '\0'), which guarantees
  // null termination.
  //
  // We deliberately restrict to the direct-assignment form and exclude
  // mayAddNullTerminator's function-call case.  The function-call case fires for
  // any call where the variable appears as an argument and the parameter is not
  // itself required to be null-terminated — this matches NetbufCopy's output
  // argument on every BAD path and would suppress all alerts.
  /** Holds if `node` is proven null-terminated by a write or guard. */
  predicate isBarrier(DataFlow::Node node) {
    exists(AssignExpr ae, VariableAccess writeVa |
      writeVa.getTarget() = node.asIndirectExpr().(VariableAccess).getTarget() and
      (
        ae.getLValue().(PointerDereferenceExpr).getOperand().getAChild*() = writeVa
        or
        ae.getLValue().(ArrayExpr).getArrayBase() = writeVa
      ) and
      not ae.getRValue().getFullyConverted().getValue().toInt() != 0
    )
    or
    // Guard-condition form: a comparison that checks whether a byte
    // derived from the tainted buffer is zero.  On the branch where
    // the byte IS zero the buffer is guaranteed null-terminated, e.g.:
    //   if (*((UINT8 *)Packet + PacketLen - 1) != 0) { return; }
    exists(GuardCondition guard, Expr deref, Expr ptrExpr, VariableAccess nodeVa |
      nodeVa = node.asIndirectExpr() and
      guard.ensuresEq(deref, 0, nodeVa.getBasicBlock(), true) and
      (
        ptrExpr = deref.(PointerDereferenceExpr).getOperand()
        or
        ptrExpr = deref.(ArrayExpr).getArrayBase()
      ) and
      ptrExpr.getAChild*().(VariableAccess).getTarget() = nodeVa.getTarget()
    )
  }

  /** Holds if `node` is a null-termination sink. */
  predicate isSink(DataFlow::Node node) { isSink(node, _) }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, VariableAccess va, FunctionCall call
where
  Flow::flowPath(sourceNode, sinkNode) and
  isSink(sinkNode.getNode(), va) and
  call.getAnArgument() = va
select call, sourceNode, sinkNode,
  "Attacker-controlled data from $@ flows to " +
    call.getTarget().getName() +
    ", which expects a null-terminated string. " +
    "If the buffer lacks a null terminator, the function may read or write out of bounds (CWE-170).",
  sourceNode.getNode(), any(string sourceType | isSource(sourceNode.getNode(), sourceType))
