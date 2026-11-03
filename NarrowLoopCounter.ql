/**
 * @name Loop counter narrower than its bound
 * @description An 8- or 16-bit loop counter compared with a wider bound wraps
 *              around before it can reach a bound above its maximum, so the
 *              loop never terminates. Counts taken from HOBs, ACPI tables or
 *              other handoff data can exceed the range of a UINT8 or UINT16
 *              counter.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id cpp/edk2-narrow-loop-counter
 * @tags security
 *       external/cwe/cwe-197
 *       external/cwe/cwe-835
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import lib.CryptoPkg.ThirdPartyCrypto

/** Gets the largest value of integral type `t`. */
float maxValue(IntegralType t) {
  if t.isUnsigned()
  then result = 2.0.pow(8 * t.getSize()) - 1
  else result = 2.0.pow(8 * t.getSize() - 1) - 1
}

/** Holds if `counter` is incremented in the body or `for` update of `loop`. */
predicate isIncrementedIn(Variable counter, Loop loop) {
  exists(Expr inc |
    inc.getEnclosingStmt().getParentStmt*() = loop.getStmt() or
    inc = loop.(ForStmt).getUpdate().getAChild*()
  |
    inc.(IncrementOperation).getOperand().(VariableAccess).getTarget() = counter or
    inc.(AssignAddExpr).getLValue().(VariableAccess).getTarget() = counter
  )
}

/**
 * Holds if `cmp`, part of `loop`'s condition, keeps the loop running while
 * `counter` has not reached `bound` (`counter < bound`, `counter <= bound`,
 * `counter != bound`).
 */
predicate isCounterBoundTest(Loop loop, ComparisonOperation cmp, VariableAccess counter, Expr bound) {
  cmp = loop.getCondition().getAChild*() and
  (
    cmp.(RelationalOperation).getLesserOperand().getUnconverted() = counter and
    bound = cmp.(RelationalOperation).getGreaterOperand()
    or
    cmp instanceof NEExpr and
    cmp.getAnOperand().getUnconverted() = counter and
    bound = cmp.getAnOperand() and
    not bound.getUnconverted() = counter
  )
}

/**
 * Holds if the variable or field that `bound` reads is compared somewhere
 * with a constant no larger than `limit`, so its range was considered, e.g.
 * `ASSERT (VertexCount < MAX_UINT16)` or a check where the count is set.
 */
bindingset[limit]
predicate isBoundCheckedElsewhere(Expr bound, float limit) {
  exists(Variable v, ComparisonOperation c, VariableAccess va, Expr k |
    bound.getUnconverted().(VariableAccess).getTarget() = v and
    va.getTarget() = v and
    c.getAnOperand().getUnconverted() = va and
    k = c.getAnOperand() and
    k.getValue().toFloat() <= limit
  )
}

from
  Loop loop, ComparisonOperation cmp, VariableAccess counter, Expr bound, IntegralType counterType,
  IntegralType boundType
where
  isCounterBoundTest(loop, cmp, counter, bound) and
  isIncrementedIn(counter.getTarget(), loop) and
  counterType = counter.getTarget().getUnspecifiedType() and
  boundType = bound.getUnconverted().getUnspecifiedType() and
  counterType.getSize() < boundType.getSize() and
  // A 32-bit counter only wraps after 4G iterations, which no firmware table or
  // HOB count reaches; reporting those would bury the 8/16-bit cases.
  counterType.getSize() < 4 and
  not bound.isConstant() and
  upperBound(bound.getFullyConverted()) > maxValue(counterType) and
  not isBoundCheckedElsewhere(bound, maxValue(counterType)) and
  // Vendored third-party crypto (OpenSSL / MbedTLS) is out of scope.
  not isThirdPartyCryptoFile(cmp.getFile())
select cmp,
  "Loop counter '" + counter.getTarget().getName() + "' (" + counter.getTarget().getType().toString() +
    ") wraps around before it can reach $@ (" + bound.getUnconverted().getType().toString() +
    "), so the loop never ends when the bound exceeds " + maxValue(counterType).toString() + ".",
  bound, bound.toString()
