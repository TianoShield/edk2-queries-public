/**
 * @name Record walker subtracts the next record's length
 * @description A loop walks a buffer of variable-length records (for example
 *              ACPI MADT or DMAR sub-tables) with a cursor and a
 *              remaining-length counter, but advances the cursor before
 *              subtracting the record length, so the subtraction reads the
 *              length of the next record. The counter then stops matching the
 *              bytes consumed: the walk reads past the end of the buffer, and
 *              a zero length in the next record stops the cursor and hangs the
 *              loop.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/edk2-record-walker-length-after-advance
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-835
 */

import cpp
import semmle.code.cpp.controlflow.SSA

/** Holds if `e` is evaluated in the body of `loop` (or a `for` update), not its condition. */
predicate isInLoopBody(Expr e, Loop loop) {
  e.getEnclosingStmt().getParentStmt*() = loop.getStmt()
  or
  e = loop.(ForStmt).getUpdate().getAChild*()
}

/**
 * Holds if `advance` moves cursor `cur` inside `loop` by a length read from
 * the record `cur` currently points to, through field `length`:
 * `cur = (T *)((UINT8 *)cur + cur->length)`.
 */
predicate isCursorAdvance(AssignExpr advance, StackVariable cur, Field length, Loop loop) {
  advance.getLValue().(VariableAccess).getTarget() = cur and
  isInLoopBody(advance, loop) and
  exists(FieldAccess fa |
    fa = advance.getRValue().getAChild*() and
    fa.getTarget() = length and
    fa.getQualifier().(VariableAccess).getTarget() = cur
  )
}

/**
 * Holds if `sub` decreases `remaining` by `amount`: `remaining -= amount` or
 * `remaining = remaining - amount`.
 */
predicate isRemainingDecrement(Assignment sub, StackVariable remaining, Expr amount) {
  sub.getLValue().(VariableAccess).getTarget() = remaining and
  (
    amount = sub.(AssignSubExpr).getRValue()
    or
    exists(SubExpr s |
      s = sub.(AssignExpr).getRValue().getUnconverted() and
      s.getLeftOperand().getUnconverted().(VariableAccess).getTarget() = remaining and
      amount = s.getRightOperand()
    )
  )
}

from
  Loop loop, StackVariable cur, StackVariable remaining, Field length, AssignExpr advance,
  Assignment sub, Expr amount, FieldAccess nextLength, SsaDefinition advanced
where
  isCursorAdvance(advance, cur, length, loop) and
  isRemainingDecrement(sub, remaining, amount) and
  isInLoopBody(sub, loop) and
  loop.getCondition().getAChild*().(VariableAccess).getTarget() = remaining and
  nextLength = amount.getAChild*() and
  nextLength.getTarget() = length and
  // The length is read through the cursor value that the advance produced, so
  // it belongs to the record after the one just consumed.
  advanced.getDefinition() = advance and
  advanced.getAUse(cur) = nextLength.getQualifier()
select sub,
  "'" + remaining.getName() + "' is reduced by the " + length.getName() + " of the record '" +
    cur.getName() + "' points to after $@ moved it to the next record, so the remaining length no longer matches the bytes consumed.",
  advance, "this advance"
