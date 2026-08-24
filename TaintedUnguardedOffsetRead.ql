/**
 * @name Unguarded constant-offset read of attacker-controlled data
 * @description Attacker-controlled bytes (a parsed image, or a received network
 *              packet) reach a `*(p + k)` / `p[k]` read for a positive constant
 *              `k` with no dominating guard that the buffer length exceeds `k`,
 *              and not gated by a validator that rejects buffers too short to
 *              hold the accessed header. EDK2 `HashPeImageByType` reads
 *              `*(AuthData + 1)` before checking the certificate is at least two
 *              bytes long (CVE-2024-38797); `Ip6ProcessRedirect` reads
 *              `*(Option + 1)` for a Neighbor Discovery option whose buffer can
 *              be a single byte when `Ip6IsNDOptionValid` has no minimum-length
 *              check (CVE-2023-45231).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cpp/edk2-tainted-unguarded-offset-read
 * @tags security
 *       external/cwe/cwe-125
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

/**
 * Holds if `deref` is a read of `base` at the positive constant offset `k`,
 * either `*(base + k)` or `base[k]`. `base` is the pointer expression whose
 * pointee bytes are read past index 0.
 *
 * The read result must be a non-pointer value (a byte/scalar of the attacker
 * buffer, as in `*(AuthData + 1)` / `*(Option + 1)` reading a `UINT8`). A
 * pointer-typed result means `base` is a table of pointers, not a contiguous
 * attacker byte buffer: a constant in-bounds index into such a fixed-size
 * pointer table (e.g. `Options[PXEBC_DHCP6_IDX_VENDOR_CLASS]` over
 * `OptList[PXEBC_DHCP6_IDX_MAX]`, whose slots merely *hold* tainted option
 * pointers) is not the byte over-read this query models, so it is excluded.
 */
predicate isConstantOffsetRead(Expr deref, Expr base, int k) {
  not deref.getType().getUnspecifiedType() instanceof PointerType and
  (
    // *(base + k)
    exists(PointerAddExpr add, Expr offExpr |
      deref.(PointerDereferenceExpr).getOperand() = add and
      add.hasOperands(base, offExpr) and
      k = offExpr.getValue().toInt() and
      k >= 1
    )
    or
    // base[k]
    exists(ArrayExpr ae |
      deref = ae and
      base = ae.getArrayBase() and
      k = ae.getArrayOffset().getValue().toInt() and
      k >= 1
    )
  )
}

/**
 * Holds if the basic block of `deref` is dominated by a guard ensuring some
 * non-constant integral length expression is `> k` (i.e. `>= k + 1`). This is
 * the in-bounds check the CVE-2024-38797 fix adds — `(AuthDataSize > 1) && ...`
 * / `(PkcsCertSize > 1) && ...` — whose true branch controls the `*(p + 1)`
 * read. Medium precision: any dominating `> k` guard counts, not only one
 * proven to be the buffer's own length.
 */
predicate hasLengthGuard(Expr deref, int k) {
  exists(GuardCondition guard, Expr lenExpr |
    // ensuresLt(e, k+1, bb, false) == "e >= k+1 holds in bb"
    guard.ensuresLt(lenExpr, k + 1, deref.getBasicBlock(), false) and
    lenExpr.getType().getUnspecifiedType() instanceof IntegralType and
    not exists(lenExpr.getValue())
  )
}

/**
 * Holds if `vf` is a minimum-length validator: an integral parameter `lenParam`
 * is compared below a positive constant and that branch returns a false-like
 * value (`0`). This is the shape of the precondition the CVE-2023-45231 fix
 * adds to `Ip6IsNDOptionValid` (`if (OptionLen < sizeof (IP6_OPTION_HEADER))
 * return FALSE;`), which rejects option buffers too short to hold an option
 * header. The vulnerable validator (without that check) only compares the length
 * against non-constant running offsets, so it does not match.
 */
predicate isMinLengthValidator(Function vf) {
  exists(
    Parameter lenParam, GuardCondition guard, BasicBlock rejectBlock, ReturnStmt rejectRet,
    int minLen
  |
    lenParam = vf.getAParameter() and
    lenParam.getType().getUnspecifiedType() instanceof IntegralType and
    // The "too short" branch (length below the constant `minLen`) returns false.
    guard.ensuresLt(lenParam.getAnAccess(), minLen, rejectBlock, true) and
    minLen >= 1 and
    rejectRet.getEnclosingFunction() = vf and
    rejectRet.getBasicBlock() = rejectBlock and
    rejectRet.getExpr().getValue().toInt() = 0
  )
}

/**
 * Holds if `deref` is reached, within its own function, after a checked call to
 * a minimum-length validator — the "validate-then-walk" pattern
 * `if (!Validate(buf, len)) <bail>; ... *(p + k)` where `Validate` rejects
 * too-short buffers. This sanitises the CVE-2023-45231 redirect read in the
 * patched tree without naming any validator: the inter-procedural minimum-length
 * check inside `Ip6IsNDOptionValid` is the only difference between the vulnerable
 * and fixed code.
 *
 * The validator's bailout does not strictly dominate the read — it is nested
 * under `if (OptionLen != 0)`, whose empty-options branch rejoins the control
 * flow before the read — so `GuardCondition.controls` does not hold. Forward
 * control-flow reachability from the checked validator call is used instead;
 * `validateCall instanceof GuardCondition` keeps it to validators whose result
 * is actually consumed by a branch.
 */
predicate isValidatedByMinLengthCheck(Expr deref) {
  exists(FunctionCall validateCall |
    isMinLengthValidator(validateCall.getTarget()) and
    validateCall instanceof GuardCondition and
    validateCall.getASuccessor+() = deref
  )
}

/**
 * Holds if `node` is the value read by an unguarded constant-offset read
 * `deref` (`*(base + k)` or `base[k]`) — the byte read past the buffer's first
 * byte with neither a local length guard nor a dominating minimum-length
 * validator call.
 *
 * The sink is the loaded value itself (`node.asExpr() = deref`), which is where
 * the buffer-content `TaintInheritingContent` deposits taint (see
 * `lib/SecurityPkg/DxeImageVerificationLib.qll` and `lib/NetworkPkg/NetLib.qll`).
 */
predicate isUnguardedOffsetReadSink(DataFlow::Node node, Expr deref, Expr base, int k) {
  isConstantOffsetRead(deref, base, k) and
  node.asExpr() = deref and
  not hasLengthGuard(deref, k) and
  not isValidatedByMinLengthCheck(deref)
}

/** Holds if `source` is a configured flow source with provenance `sourceType`. */
predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

module Config implements DataFlow::ConfigSig {
  /** Holds if `node` is one of the configured flow sources. */
  predicate isSource(DataFlow::Node node) { isSource(node, _) }

  /** Holds if `node` is the value read by an unguarded constant-offset deref. */
  predicate isSink(DataFlow::Node node) { isUnguardedOffsetReadSink(node, _, _, _) }

  /** Holds if `node` is known to block unsafe flow. */
  predicate isBarrier(DataFlow::Node node) {
    // Vendored third-party crypto (OpenSSL / MbedTLS) manages its own buffers
    // and is out of scope; block all flow through it.
    isThirdPartyCryptoNode(node)
  }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode sourceNode, Flow::PathNode sinkNode, Expr deref, Expr base, int k
where
  Flow::flowPath(sourceNode, sinkNode) and
  isUnguardedOffsetReadSink(sinkNode.getNode(), deref, base, k)
select deref, sourceNode, sinkNode,
  "Out-of-bounds read: attacker-controlled data from $@ is read at constant offset " + k +
    " with no guard that the buffer length exceeds " + k + ".", sourceNode.getNode(),
  any(string t | isSource(sourceNode.getNode(), t))
