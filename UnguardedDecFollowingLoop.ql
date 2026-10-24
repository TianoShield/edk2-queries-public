/**
 * @id cpp/cve-2024-38805-unguarded-dec-following-loop
 * @name Unguarded length decrement following a length depleting loop (CVE-2024-38805 pattern A)
 * @description Finds a preceding `while (Len > 0 && ...)`-style scan loop drains unsigned length and a later decrement occurs without a post-scan `(Len > 0)`-style guard.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @tags security
 *       external/cwe/cwe-191
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp
import lib.CryptoPkg.ThirdPartyCrypto

private predicate isUnsignedIntegralVar(Variable v) {
  exists(IntegralType t |
    t = v.getType().getUnspecifiedType() and
    t.isUnsigned()
  )
}

private predicate conditionUsesVar(Expr cond, Variable v) {
  exists(VariableAccess va |
    va.getTarget() = v and
    va.getParent*() = cond
  )
}

private predicate isNestedInsideStmt(ControlFlowNode e, Stmt s) {
  e.getEnclosingStmt().getParentStmt*() = s
}

private predicate decrementsVarInStmt(Stmt s, Variable v, DecrementOperation dec) {
  isNestedInsideStmt(dec, s) and
  exists(VariableAccess va |
    va = dec.getOperand().getFullyConverted() and
    va.getTarget() = v
  )
}

private predicate occursAfter(ControlFlowNode first, ControlFlowNode second) {
  first.getASuccessor*() = second and
  second.getAPredecessor*() = first
}

private predicate isZero(Expr e) {
  e.getValue().toInt() = 0
}

private predicate hasLenGreaterThanZeroCheck(Expr cond, Variable lenVar) {
  exists(RelationalOperation cmp |
    cmp.getParent*() = cond and
    isZero(cmp.getLesserOperand()) and
    conditionUsesVar(cmp.getGreaterOperand(), lenVar)
  )
}

private predicate isLengthDepletingScanLoop(Loop scanLoop, Variable lenVar) {
  conditionUsesVar(scanLoop.getCondition(), lenVar) and
  hasLenGreaterThanZeroCheck(scanLoop.getCondition(), lenVar) and
  exists(DecrementOperation dec |
    decrementsVarInStmt(scanLoop.getStmt(), lenVar, dec)
  )
}

private predicate isPostScanLenGuarded(DecrementOperation dec, Variable lenVar, Loop scanLoop) {
  exists(IfStmt ifs |
    occursAfter(scanLoop, ifs) and
    hasLenGreaterThanZeroCheck(ifs.getCondition(), lenVar) and
    isNestedInsideStmt(dec, ifs.getThen())
  )
  or
  exists(Loop guardedLoop |
    occursAfter(scanLoop, guardedLoop) and
    hasLenGreaterThanZeroCheck(guardedLoop.getCondition(), lenVar) and
    isNestedInsideStmt(dec, guardedLoop.getStmt())
  )
}

from Loop scanLoop, Variable lenVar, DecrementOperation unguardedDec
where
  isUnsignedIntegralVar(lenVar) and
  isLengthDepletingScanLoop(scanLoop, lenVar) and
  unguardedDec.getEnclosingFunction() = scanLoop.getEnclosingFunction() and
  exists(VariableAccess decVar |
    decVar = unguardedDec.getOperand().getFullyConverted() and
    decVar.getTarget() = lenVar
  ) and
  occursAfter(scanLoop, unguardedDec) and
  not isNestedInsideStmt(unguardedDec, scanLoop.getStmt()) and
  not isPostScanLenGuarded(unguardedDec, lenVar, scanLoop) and
  // Vendored third-party crypto (OpenSSL / MbedTLS) manages its own buffers and
  // is out of scope for this EDK2-focused query.
  not isThirdPartyCryptoFile(unguardedDec.getLocation().getFile())
select unguardedDec,
  "CVE-2024-38805 Pattern A (Length-Depleting Scan Loop Followed by Unguarded Decrement): unsigned " +
  lenVar.getName() + " is decremented in a preceding scan loop and later decremented again without a post-scan (Len > 0)-style guard."
