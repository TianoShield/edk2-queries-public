/**
 * @name Fixed-size access to a buffer allocated with an attacker-controlled size
 * @description Tracks tainted flow from attacker-controlled remote input to the
 *              allocation-size argument of an EDK2 pool allocator whose result is
 *              then accessed by a BaseMemoryLib operation (CopyMem/CompareMem/
 *              SetMem/...) of a compile-time-constant length. When the attacker
 *              can make the allocation smaller than that fixed length, the
 *              operation reads or writes past the under-allocated buffer. This is
 *              the inverse of a tainted-length overflow (TaintedBaseMemoryLibLength):
 *              here the length is constant and the allocation size is the
 *              attacker-controlled value.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/tainted-allocation-fixed-access-length
 * @tags security
 *       external/cwe/cwe-131
 *       external/cwe/cwe-787
 *       external/cwe/cwe-125
 *       external/cwe/cwe-122
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.models.implementations.Allocation
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

/**
 * Holds if `call` is a BaseMemoryLib block operation that accesses buffer `buf`
 * for a compile-time-constant byte count `len` (the access is fixed-size,
 * independent of any attacker value). The buffer/length argument layout is taken
 * from the shared `baseMemoryLibBufferParameter` model.
 *
 * Requiring `len` to be a constant is what distinguishes this query from
 * TaintedBaseMemoryLibLength: a fixed-size access cannot be bounded by an
 * attacker-undersized buffer, so the out-of-bounds comes from the allocation,
 * not the length.
 */
predicate baseMemoryLibFixedAccess(FunctionCall call, Expr buf, Expr len) {
  exists(int bufParam, int lengthParam |
    baseMemoryLibBufferParameter(call.getTarget(), bufParam, lengthParam) and
    buf = call.getArgument(bufParam) and
    len = call.getArgument(lengthParam)
  ) and
  exists(len.getValue())
}

/**
 * Holds if `bufferUse` reads back the buffer that `alloc` allocated.
 *
 * `DataFlow::localExprFlow` handles the common case where the pointer is held in
 * a local (SSA) variable (`T p = alloc; CopyMem(p, ..)`), flow-sensitively. It
 * does *not*, however, carry a value through a struct-field store and reload —
 * although the global dataflow solver is field-sensitive, the local-flow
 * relation is not. So the second disjunct adds exactly that gap structurally:
 * `q->f = alloc` then a read `q->f` (CVE-2023-45234:
 * `Private->DnsServer = AllocateZeroPool(...); CopyMem(Private->DnsServer, ..)`),
 * matched by the same `Field` on qualifiers with the same global value number.
 */
predicate allocStoredInto(AllocationExpr alloc, Expr bufferUse) {
  DataFlow::localExprFlow(alloc, bufferUse)
  or
  exists(AssignExpr a, FieldAccess store, FieldAccess load |
    a.getRValue() = alloc and
    store = a.getLValue() and
    load = bufferUse and
    store.getTarget() = load.getTarget() and
    globalValueNumber(store.getQualifier()) = globalValueNumber(load.getQualifier())
  )
}

/**
 * Holds if `node` is the allocation-size argument of `alloc`, an EDK2 pool
 * allocation whose buffer is later accessed by the fixed-size BaseMemoryLib
 * operation `access`. An attacker-controlled value reaching `node` can under-size
 * the buffer relative to the constant access length.
 */
predicate isTaintedAllocSizeSink(DataFlow::Node node, AllocationExpr alloc, FunctionCall access) {
  node.asExpr() = alloc.getSizeExpr() and
  exists(Expr buf | baseMemoryLibFixedAccess(access, buf, _) and allocStoredInto(alloc, buf))
}

/**
 * Holds if `node` is an allocation size that a dominating guard constrains to be
 * at least the fixed access length `c` it feeds, so the buffer cannot be
 * under-allocated. The bound may be on the value itself or on a composite that
 * contains it (matched by global value number, as in TaintedBaseMemoryLibLength).
 *
 * This silences the natural patch shape `if (size < sizeof(T)) reject;` before
 * `buf = AllocatePool(size); CopyMem(buf, .., sizeof(T))`. The actual
 * CVE-2023-45234 fix instead allocates a constant `sizeof (EFI_IPv6_ADDRESS)`,
 * which already drops out because a constant size carries no taint.
 */
predicate isSizeLowerBoundGuarded(DataFlow::Node node) {
  exists(AllocationExpr alloc, FunctionCall access, Expr buf, Expr len, int c |
    node.asExpr() = alloc.getSizeExpr() and
    baseMemoryLibFixedAccess(access, buf, len) and
    allocStoredInto(alloc, buf) and
    c = len.getValue().toInt()
  |
    // `ensuresLt(guarded, k, bb, false)` means `guarded >= k` is guaranteed in
    // `bb`; requiring `k >= c` proves the allocation is at least the access size.
    exists(GuardCondition g, Expr guarded, int k |
      g.ensuresLt(guarded, k, node.asExpr().getBasicBlock(), false) and
      k >= c
    |
      globalValueNumber(guarded) = globalValueNumber(node.asExpr())
      or
      globalValueNumber(guarded.getAChild+()) = globalValueNumber(node.asExpr())
    )
  )
}

/**
 * Holds if `source` is a configured flow source and `sourceType` is its
 * user-facing provenance string. All sources are modeled as `RemoteFlowSource`
 * / `LocalFlowSource` subclasses in `lib/` — including the PXE BC cached DHCPv6
 * option index table (`Edk2PxeBcDhcp6OptListSource`) that seeds CVE-2023-45234.
 */
predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

module Config implements DataFlow::ConfigSig {
  /** Holds if `node` is one of the configured flow sources. */
  predicate isSource(DataFlow::Node node) { isSource(node, _) }

  /** Holds if `node` is the size argument of an under-sizeable pool allocation. */
  predicate isSink(DataFlow::Node node) { isTaintedAllocSizeSink(node, _, _) }

  /**
   * Holds if `node` is an allocation size already constrained from below by a
   * dominating guard, so the buffer cannot be under-allocated relative to the
   * fixed access (alert only on *unguarded* attacker sizes).
   */
  predicate isBarrier(DataFlow::Node node) {
    isSizeLowerBoundGuarded(node)
    or
    // Vendored third-party crypto (OpenSSL / MbedTLS) manages its own buffers
    // and is out of scope; block all flow through it.
    isThirdPartyCryptoNode(node)
  }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, AllocationExpr alloc, FunctionCall access
where
  Flow::flowPath(sourceNode, sinkNode) and
  isTaintedAllocSizeSink(sinkNode.getNode(), alloc, access)
select access, sourceNode, sinkNode,
  "Buffer allocated with an attacker-controlled size from $@ is then accessed by " +
    access.getTarget().getName() +
    " with a fixed length, which can read or write past the under-allocated buffer.",
  sourceNode.getNode(), any(string sourceType | isSource(sourceNode.getNode(), sourceType))
