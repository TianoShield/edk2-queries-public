/**
 * @name Unchecked random number generator result
 * @description The success result of an RNG call is discarded or only
 *              asserted. When the generator fails, the output buffer is left
 *              unwritten (often uninitialized stack), and the caller goes on
 *              to use it as a salt, key or nonce.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id cpp/edk2-unchecked-random-number-result
 * @tags security
 *       external/cwe/cwe-252
 *       external/cwe/cwe-330
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import lib.Edk2

/**
 * Holds if the result of `call` leaves its function: it is returned, or it
 * guards a `return`, as in `if (!RandomBytes (...)) { return FALSE; }`.
 */
predicate propagatesResult(Call call) {
  exists(ReturnStmt r, Expr use | DataFlow::localExprFlow(call, use) |
    use = r.getExpr().getAChild*()
    or
    exists(GuardCondition g | use = g.(Expr).getAChild*() and g.controls(r.getBasicBlock(), _))
  )
}

/**
 * Gets the argument of `call` that points to the buffer receiving random
 * data, when `call` reports whether that data was produced: a modeled RNG
 * call, or a call to a wrapper (`isRandomNumberWrapper`).
 */
Expr randomOutputArgument(Call call) {
  result = call.(Edk2RandomNumberCall).getOutputArgument()
  or
  exists(Parameter p |
    isRandomNumberWrapper(call.getTarget(), p) and
    result = call.getArgument(p.getIndex())
  )
}

/**
 * Holds if `wrapper` fills the buffer its parameter `p` points to with the
 * output of an RNG call and passes that call's result on, so its callers
 * inherit the obligation to check it. Examples are KeyLibGenerateSalt
 * (`SaltValue`) and RdRandGenerateEntropy (`Entropy`, filled by `CopyMem`
 * from a local seed). A function that only fails when an internal RNG call
 * fails, such as SavePasswordToVariable, is not a wrapper: its random data
 * never reaches the caller.
 */
predicate isRandomNumberWrapper(Function wrapper, Parameter p) {
  exists(Call inner, DataFlow::Node random, DataFlow::PostUpdateNode written, Expr pointer |
    inner.getEnclosingFunction() = wrapper and
    propagatesResult(inner) and
    random.asDefiningArgument() = randomOutputArgument(inner) and
    // The random bytes are written through `pointer` (the RNG output argument
    // itself, or for example a `CopyMem` destination) ...
    TaintTracking::localTaint(random, written) and
    written.getPreUpdateNode().asIndirectExpr() = pointer and
    // ... which points into the caller's buffer.
    p.getFunction() = wrapper and
    TaintTracking::localTaint(DataFlow::parameterNode(p), DataFlow::exprNode(pointer))
  )
}

/** Holds if `call` reports whether random data was produced. */
predicate isRandomNumberCall(Call call) { exists(randomOutputArgument(call)) }

/**
 * Holds if the result of `call` is tested by a branch outside a DebugLib
 * assertion, or is passed on to the caller.
 */
predicate isChecked(Call call) {
  exists(Expr use, GuardCondition g |
    DataFlow::localExprFlow(call, use) and
    not isInDebugAssertion(use) and
    use = g.(Expr).getAChild*() and
    // IR guards include any value-producing expression; only one that
    // decides a branch is a check.
    g.controls(_, _)
  )
  or
  propagatesResult(call)
}

/** Gets a name for the function or protocol member that `call` invokes. */
string calleeName(Call call) {
  result = call.(FunctionCall).getTarget().getName()
  or
  result = call.(ExprCall).getExpr().(FieldAccess).getTarget().getName()
}

from Call call
where
  isRandomNumberCall(call) and
  not isChecked(call)
select call,
  "The result of " + calleeName(call) +
    " is not checked; when the generator fails, its output buffer is used without random data."
