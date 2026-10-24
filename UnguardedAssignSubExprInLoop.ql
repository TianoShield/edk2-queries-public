/**
 * @id cpp/cve-2024-38805-unguarded-assignsubexpr-in-loop
 * @name Unguarded AssignSubExpr in loop (CVE-2024-38805 pattern B)
 * @description Finds unsigned loop-control variables compared with 0 and decremented via `-=` in the loop body, excluding guarded and known-safe patterns.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-191
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.SSA
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import lib.CryptoPkg.ThirdPartyCrypto

private predicate isUnsignedIntegralVar(Variable v) {
  exists(IntegralType t |
    t = v.getType().getUnspecifiedType() and
    t.isUnsigned()
  )
}

private predicate condComparesVarWithZero(Expr cond, Variable v) {
  exists(ComparisonOperation cmp, VariableAccess va, Expr zero |
    cmp.getParent*() = cond and
    va.getTarget() = v and
    va.getParent*() = cmp and
    zero.getFullyConverted().getValue().toInt() = 0 and
    cmp.hasOperands(va, zero)
  )
}

private predicate sameValueExpr(Expr a, Expr b) {
  globalValueNumber(a) = globalValueNumber(b)
  or
  exists(VariableAccess va, VariableAccess vb |
    va = a.getUnconverted() and
    vb = b.getUnconverted() and
    va.getTarget() = vb.getTarget()
  )
  or
  exists(FieldAccess fa, FieldAccess fb |
    fa = a.getUnconverted() and
    fb = b.getUnconverted() and
    fa.getTarget() = fb.getTarget()
  )
}

/**
 * Matches EDK2's `MIN` macro `#define MIN(a, b) (((a) < (b)) ? (a) : (b))`
 * and e is an argument of the macro.
 */
private predicate isMinTernary(Expr minMacro, Expr e) {
  exists(ConditionalExpr c, RelationalOperation cmp |
    c = minMacro.getUnconverted() and
    cmp = c.getCondition().getUnconverted() and
    sameValueExpr(cmp.getLesserOperand(), c.getThen()) and
    sameValueExpr(cmp.getGreaterOperand(), c.getElse()) and
    (
      sameValueExpr(c.getThen(), e)
      or
      sameValueExpr(c.getElse(), e)
    )
  )
}

private predicate rhsAssignedFromMinOfLhs(AssignSubExpr sub) {
  exists(VariableAccess rhsUse, StackVariable rhsVar, SsaDefinition reachingDef, Expr subLhs |
    rhsUse = sub.getRValue().getUnconverted() and
    rhsVar = rhsUse.getTarget() and
    subLhs = sub.getLValue().getFullyConverted() and
    reachingDef.getAUse(rhsVar) = rhsUse and
    exists(Expr someDefExpr |
      someDefExpr = reachingDef.getAnUltimateDefiningValue(rhsVar)
    ) and
    forall(Expr defExpr |
      defExpr = reachingDef.getAnUltimateDefiningValue(rhsVar)
      |
      isMinTernary(defExpr, subLhs)
    )
  )
}

private predicate hasGuardEnsuringLhsGeRhs(AssignSubExpr sub) {
  exists(Expr subLhs, Expr subRhs |
    subLhs = sub.getLValue() and
    subRhs = sub.getRValue() and
    exists(GuardCondition guard, int k, BasicBlock bb, Expr left, Expr right |
      bb = sub.getBasicBlock() and
      sameValueExpr(left, subLhs) and
      sameValueExpr(right, subRhs) and
      guard.controls(bb, _) and
      // left >= right + k >= right
      guard.ensuresLt(left, right, k, bb, false) and
      k >= 0
    )
  )
}

private predicate hasGuardEnsuringLhsGeConstRhs(AssignSubExpr sub) {
  exists(Expr subLhs, int rhsK |
    subLhs = sub.getLValue() and
    rhsK = sub.getRValue().getFullyConverted().getValue().toInt() and
    rhsK >= 0 and
    exists(GuardCondition guard, BasicBlock bb, Expr left |
      bb = sub.getBasicBlock() and
      sameValueExpr(left, subLhs) and
      guard.controls(bb, _) and
      guard.ensuresLt(left, rhsK, bb, false)
    )
  )
}

bindingset[n]
private predicate isPowerOfTwoInt(int n) {
  n > 0 and
  n.bitAnd(n - 1) = 0
}

/**
 * Holds if `andExpr` is a bitwise AND expression of the form `xxx & ~(exp - 1)` where `exp` is a power of two
 */
private predicate isBitwiseAndWithNotExpMinusOne(BitwiseAndExpr andExpr, Expr exp) {
  exists(int sz, ComplementExpr notSzMinusOneExpr, SubExpr szMinusOneExpr |
    sz = exp.getFullyConverted().getValue().toInt() and
    isPowerOfTwoInt(sz) and
    andExpr.getAnOperand() = notSzMinusOneExpr and
    szMinusOneExpr = notSzMinusOneExpr.getOperand().getUnconverted() and
    szMinusOneExpr.getLeftOperand().getFullyConverted().getValue().toInt() = sz and
    szMinusOneExpr.getRightOperand().getFullyConverted().getValue().toInt() = 1
  )
}

private predicate hasSsaDefShowingLhsMultipleOfRhs(AssignSubExpr sub) {
  exists(VariableAccess lhsUse, StackVariable lhsVar, SsaDefinition lhsDef, Expr lhsDefExpr |
    lhsUse = sub.getLValue().getUnconverted() and
    lhsVar = lhsUse.getTarget() and
    lhsDef.getAUse(lhsVar) = lhsUse and
    lhsDefExpr = lhsDef.getAnUltimateDefiningValue(lhsVar) and
    isBitwiseAndWithNotExpMinusOne(lhsDefExpr.getUnconverted(), sub.getRValue())
  )
}

/**
 * Matches a simple budgeted receive pattern:
 * `lhs = ...->BufSize; rhs = SockProcessRcvToken(...); lhs -= rhs;`
 */
private predicate hasBufSizeBudgetedSockProcessRcvTokenPattern(AssignSubExpr sub) {
  exists(
    VariableAccess subLhsUse, StackVariable lhsVar, SsaDefinition lhsDef, Expr lhsDefExpr, FieldAccess bufSizeField,
    VariableAccess subRhsUse, StackVariable rhsVar, SsaDefinition rhsDef, Expr rhsDefExpr, FunctionCall rhsCall
  |
    subLhsUse = sub.getLValue().getUnconverted() and
    lhsVar = subLhsUse.getTarget() and
    lhsDef.getAUse(lhsVar) = subLhsUse and
    lhsDefExpr = lhsDef.getAnUltimateDefiningValue(lhsVar) and
    bufSizeField = lhsDefExpr.getUnconverted() and
    bufSizeField.getTarget().getName() = "BufSize" and
    subRhsUse = sub.getRValue().getUnconverted() and
    rhsVar = subRhsUse.getTarget() and
    rhsDef.getAUse(rhsVar) = subRhsUse and
    rhsDefExpr = rhsDef.getAnUltimateDefiningValue(rhsVar) and
    rhsCall = rhsDefExpr.getUnconverted() and
    rhsCall.getTarget().getName() = "SockProcessRcvToken"
  )
}

from WhileStmt loop, Variable lenVar, AssignSubExpr lenSubtract
where
  isUnsignedIntegralVar(lenVar) and
  condComparesVarWithZero(loop.getCondition(), lenVar) and
  lenSubtract.getEnclosingStmt().getParent*() = loop.getStmt() and
  exists(VariableAccess lhs |
    lhs = lenSubtract.getLValue().getFullyConverted() and
    lhs.getTarget() = lenVar
  ) and
  // has guard lhs >= rhs
  not hasGuardEnsuringLhsGeRhs(lenSubtract) and
  // has guard lhs >= rhs where rhs is a constant >= 0
  not hasGuardEnsuringLhsGeConstRhs(lenSubtract) and
  // rhs = MIN(lhs, ..) or MIN(.., lhs) <= lhs
  // This case cannot be detected with the above GuardCondition predicates.
  not rhsAssignedFromMinOfLhs(lenSubtract) and
  // lhs = xxx & ~(rhs - 1) where rhs is a power of two, and loop condition is lhs != 0
  // lhs is a multiple of rhs
  not hasSsaDefShowingLhsMultipleOfRhs(lenSubtract) and
  // lhs = ...->BufSize; rhs = SockProcessRcvToken(...); lhs -= rhs
  not hasBufSizeBudgetedSockProcessRcvTokenPattern(lenSubtract) and
  // Vendored third-party crypto (OpenSSL / MbedTLS) manages its own buffers and
  // is out of scope for this EDK2-focused query.
  not isThirdPartyCryptoFile(lenSubtract.getLocation().getFile())
select lenSubtract,
  "Unsigned " + lenVar.getName() +
  " controls a loop condition (compared with 0) and is decremented with '-=' without a proven lhs >= rhs guard."
