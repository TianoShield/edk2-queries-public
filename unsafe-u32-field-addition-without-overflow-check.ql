/**
 * @id cpp/unsafe-u32-field-addition-without-overflow-check
 * @name Unsafely adding unsigned 32-bit fields without overflow guard
 * @description Finds range/end computations that add two unsigned <=32-bit struct fields without a nearby overflow check (for example: `start + size - 1`).
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @tags security
 *       external/cwe/cwe-190
 */

import cpp

private predicate asFieldAccess(Expr e, FieldAccess fa) {
  fa = e.getFullyConverted().(FieldAccess)
}

private predicate hasRootVariable(FieldAccess fa, Variable v) {
  exists(VariableAccess va |
    va.getTarget() = v and
    (va = fa.getQualifier() or va.getParent*() = fa.getQualifier())
  )
}

private predicate sameQualifierAst(Expr a, Expr b) {
  exists(VariableAccess va, VariableAccess vb |
    va = a.getFullyConverted() and
    vb = b.getFullyConverted() and
    va.getTarget() = vb.getTarget()
  )
  or
  exists(FieldAccess fa, FieldAccess fb |
    fa = a.getFullyConverted() and
    fb = b.getFullyConverted() and
    fa.getTarget() = fb.getTarget() and
    sameQualifierAst(fa.getQualifier(), fb.getQualifier())
  )
}

private predicate sameObject(FieldAccess a, FieldAccess b) {
  exists(Variable v |
    hasRootVariable(a, v) and
    hasRootVariable(b, v)
  )
  or
  sameQualifierAst(a.getQualifier(), b.getQualifier())
}

private predicate sameFieldAccess(FieldAccess a, FieldAccess b) {
  a.getTarget() = b.getTarget() and
  sameObject(a, b)
}

private predicate isUnsigned32OrLess(AddExpr add) {
  exists(IntegralType t |
    t = add.getType() and
    t.isUnsigned() and
    t.getSize() <= 4
  )
}

private predicate isRangeLikeUse(AddExpr add) {
  add.getParent() instanceof SubExpr
  or
  add.getParent() instanceof RelationalOperation
  or
  add.getParent() instanceof FunctionCall
}

private predicate hasNearbyOverflowGuard(AddExpr add, FieldAccess base, FieldAccess size) {
  exists(IfStmt ifs, Expr cond |
    ifs.getFile() = add.getFile() and
    ifs.getEnclosingFunction() = add.getEnclosingFunction() and
    cond = ifs.getCondition() and
    ifs.getLocation().getStartLine() < add.getLocation().getStartLine() and
    add.getLocation().getStartLine() - ifs.getLocation().getStartLine() <= 40 and
    (
      // Pattern: (MAX - base) < size  or  (MAX - base) <= size
      exists(RelationalOperation cmp, SubExpr diff, FieldAccess gBase, FieldAccess gSize |
        cmp.getParent*() = cond and
        (cmp instanceof LTExpr or cmp instanceof LEExpr) and
        diff = cmp.getLeftOperand().getFullyConverted().(SubExpr) and
        asFieldAccess(diff.getRightOperand(), gBase) and
        asFieldAccess(cmp.getRightOperand(), gSize) and
        sameFieldAccess(gBase, base) and
        sameFieldAccess(gSize, size)
      )
      or
      // Pattern: base > (MAX - size)  or  base >= (MAX - size)
      exists(RelationalOperation cmp, SubExpr diff, FieldAccess gBase, FieldAccess gSize |
        cmp.getParent*() = cond and
        (cmp instanceof GTExpr or cmp instanceof GEExpr) and
        asFieldAccess(cmp.getLeftOperand(), gBase) and
        diff = cmp.getRightOperand().getFullyConverted().(SubExpr) and
        asFieldAccess(diff.getRightOperand(), gSize) and
        sameFieldAccess(gBase, base) and
        sameFieldAccess(gSize, size)
      )
    )
  )
}

from AddExpr add, FieldAccess lhs, FieldAccess rhs
where
  isUnsigned32OrLess(add) and
  isRangeLikeUse(add) and
  asFieldAccess(add.getLeftOperand(), lhs) and
  asFieldAccess(add.getRightOperand(), rhs) and
  sameObject(lhs, rhs) and
  not hasNearbyOverflowGuard(add, lhs, rhs) and
  not hasNearbyOverflowGuard(add, rhs, lhs)
select add,
  "Potential unsigned overflow in range computation: " + lhs.toString() + " + " + rhs.toString() +
  " has no nearby overflow guard (for example, MAX - a < b)."
