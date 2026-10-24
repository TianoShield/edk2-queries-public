/**
 * @name Tainted remote input reaches BaseMemoryLib length argument
 * @description Tracks tainted flow from attacker-controlled remote input to the
 *              length argument of BaseMemoryLib functions (CompareMem, CopyMem,
 *              SetMem, ZeroMem, ScanMem*, etc.) with no dominating upper-bound
 *              guard, which can cause out-of-bounds memory access.
 *
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/tainted-basememorylib-length-from-udpio-callback
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 *       external/cwe/cwe-805
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

/**
 * Holds if `node` is the length argument of a BaseMemoryLib block call `call`
 * (`CopyMem`/`CompareMem` length index 2, `SetMem*`/`ZeroMem`/`ScanMem*`/
 * `IsZeroBuffer` length index 1), taken from the `baseMemoryLibBufferParameter`
 * model so no function name or index is hardcoded here. `NetbufCopy` is excluded
 * because its own bounds arithmetic wraps these calls with the copy already
 * clamped to the destination.
 */
predicate baseMemoryLibLengthArg(DataFlow::Node node, FunctionCall call) {
  exists(int lengthParam |
    baseMemoryLibBufferParameter(call.getTarget(), _, lengthParam) and
    node.asExpr() = call.getArgument(lengthParam)
  ) and
  not call.getEnclosingFunction().hasName("NetbufCopy")
}

/**
 * Holds if `source` is a configured flow source and `sourceType` is its
 * user-facing provenance string. All sources are modeled as `RemoteFlowSource`
 * / `LocalFlowSource` subclasses in `lib/` — including the PXE BC cached DHCPv6
 * packets (`Edk2PxeBcCachedDhcp6PacketSource` in `lib/NetworkPkg/PxeBcDhcp6.qll`)
 * that seed CVE-2023-45235, and the Dhcp6Dxe cached Advertise/Reply packets
 * (`Edk2Dhcp6CachedPacketSource` in `lib/NetworkPkg/Dhcp6Dxe.qll`) that seed
 * CVE-2023-45230.
 */
predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

/**
 * Barrier: holds if a dominating guard already bounds the tainted length `node`
 * from above before the copy, so it cannot overflow. Only unguarded lengths are
 * reported.
 *
 * `g.ensuresLt(guarded, bound, k, block, true)` says the guard forces
 * `guarded < bound + k` throughout the copy's `block`. A length is suppressed
 * when it is the guarded value, or a sub-expression of it (e.g. `len` inside
 * the guarded expr `len + ...`).
 *
 * The `guardedVal` step uses global value numbering. It matters when `node` is
 * not guarded directly: instead `node` is used to compute a temporary local
 * variable, and that variable is the one guarded. As in the CVE-2023-45230
 * patch:
 *
 *     BytesNeeded = ... + NTOHS(OptLen);
 *     if (Length < BytesNeeded) reject;
 *
 * Here `guarded` is the bare `BytesNeeded` access, which has no children,
 * so the tainted length `NTOHS(OptLen)` is not a sub-expression of it. GVN
 * recovers the assigned value `... + NTOHS(OptLen)` (same value number as
 * `BytesNeeded`) as `guardedVal`, and the tainted length is a sub-expression
 * of that — so the guard still applies.
 */
predicate isUpperBoundGuarded(DataFlow::Node node) {
  exists(GuardCondition g, Expr guarded, Expr bound, int k, Expr guardedVal |
    g.ensuresLt(guarded, bound, k, node.asExpr().getBasicBlock(), true) and
    globalValueNumber(guardedVal) = globalValueNumber(guarded)
  |
    globalValueNumber(guardedVal) = globalValueNumber(node.asExpr())
    or
    globalValueNumber(guardedVal.getAChild+()) = globalValueNumber(node.asExpr())
  )
}

/**
 * Barrier: holds if `node` is a BaseMemoryLib length reached inside one of the
 * internal MemoryAllocationLib pool workers (`isInternalAllocationFunction`).
 * These routines `ZeroMem`/`CopyMem` the buffer they have just allocated with
 * the very allocation size, so the access is definitionally in bounds; flagging
 * it is a library echo, not a real finding.
 */
predicate isInInternalAllocation(DataFlow::Node node) {
  isInternalAllocationFunction(node.asExpr().getEnclosingFunction())
}

module Config implements DataFlow::ConfigSig {
  /** Holds if `node` is one of the shared attacker flow sources. */
  predicate isSource(DataFlow::Node node) { node instanceof FS::FlowSource }

  /**
   * Holds if `node` is the length argument of a BaseMemoryLib call. With the
   * buffer-capacity restriction disabled (see the commented-out block above),
   * every such length argument is a sink.
   */
  predicate isSink(DataFlow::Node node) { baseMemoryLibLengthArg(node, _) }

  /**
   * Holds if `node` is an attacker length that is not reported: a dominating
   * upper-bound guard already constrains it (`isUpperBoundGuarded`), it is in
   * out-of-scope vendored OpenSSL code that manages its own buffers
   * (`isOpensslNode`), or it is a library echo inside an internal pool allocator
   * writing the buffer it just allocated (`isInInternalAllocation`).
   */
  predicate isBarrier(DataFlow::Node node) {
    isUpperBoundGuarded(node) or
    isOpensslNode(node) or
    isInInternalAllocation(node)
  }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, FunctionCall call
where
  Flow::flowPath(sourceNode, sinkNode) and
  baseMemoryLibLengthArg(sinkNode.getNode(), call)
select call, sourceNode, sinkNode,
  "Attacker-controlled length from $@ flows to the length argument of " +
    call.getTarget().getName() + ", potentially causing an out-of-bounds memory access.",
  sourceNode.getNode(), any(string sourceType | isSource(sourceNode.getNode(), sourceType))
