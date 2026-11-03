/**
 * @name Secret left in a stack buffer
 * @description A local buffer holds secret data (it is passed to a password
 *              or key consumer such as Pkcs5HashPassword), but the function
 *              can return without clearing it. The secret stays in stack
 *              memory, which is SMRAM for an SMI handler, where a later
 *              memory disclosure can recover it.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision high
 * @id cpp/edk2-uncleared-stack-secret
 * @tags security
 *       external/cwe/cwe-226
 *       external/cwe/cwe-244
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import lib.Edk2

/** Gets the variable at the root of the lvalue `e` (`v`, `v.f`, `v[i]`, `v.f[i]`, `&...`). */
Variable rootVariable(Expr e) {
  result = e.(VariableAccess).getTarget() and not e instanceof PointerFieldAccess
  or
  result = rootVariable(e.(ValueFieldAccess).getQualifier().getUnconverted())
  or
  result = rootVariable(e.(ArrayExpr).getArrayBase().getUnconverted())
  or
  result = rootVariable(e.(AddressOfExpr).getOperand().getUnconverted())
}

/**
 * Holds if `e` evaluates to an address inside the stack buffer `v`: `&v`,
 * `&v.Field`, or an array (`v`, `v.Field`) that decays to a pointer.
 */
predicate isAddressInto(Expr e, LocalVariable v) {
  not v.isStatic() and
  rootVariable(e) = v and
  (e instanceof AddressOfExpr or e.getUnspecifiedType() instanceof ArrayType)
}

/** Tracks addresses of stack buffers into parameters that receive secrets. */
module SecretBufferConfig implements DataFlow::ConfigSig {
  /** Holds if `node` is an address inside a stack buffer. */
  predicate isSource(DataFlow::Node node) { isAddressInto(node.asExpr(), _) }

  /** Holds if `node` is an argument passed to a secret parameter (`isSecretParameter`). */
  predicate isSink(DataFlow::Node node) {
    exists(FunctionCall call, int i |
      isSecretParameter(call.getTarget(), i) and node.asExpr() = call.getArgument(i)
    )
  }
}

module SecretBufferFlow = DataFlow::Global<SecretBufferConfig>;

/** Holds if `use` is an address inside `v` that flows to the secret argument of `consumer`. */
predicate isSecretUse(Expr use, LocalVariable v, FunctionCall consumer) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    SecretBufferFlow::flow(source, sink) and
    source.asExpr() = use and
    isAddressInto(use, v) and
    sink.asExpr() = consumer.getAnArgument()
  )
}

/** Holds if `call` zeroes (part of) the stack buffer `v`. */
predicate clears(ControlFlowNode call, LocalVariable v) {
  exists(Expr buffer | isZeroingCall(call, buffer) and rootVariable(buffer.getUnconverted()) = v)
}

/**
 * Holds if the exit of `v`'s function can be reached from `n` without passing
 * a call that clears `v`.
 */
predicate reachesExitUncleared(ControlFlowNode n, LocalVariable v) {
  isSecretUse(_, v, _) and
  n = v.getFunction()
  or
  exists(ControlFlowNode succ |
    reachesExitUncleared(succ, v) and
    succ = n.getASuccessor() and
    not clears(n, v)
  )
}

from LocalVariable v, Expr use, FunctionCall consumer
where
  use =
    min(Expr u, Location l |
      isSecretUse(u, v, _) and reachesExitUncleared(u, v) and l = u.getLocation()
    |
      u order by l.getStartLine(), l.getStartColumn()
    ) and
  isSecretUse(use, v, consumer)
select v,
  "Stack buffer '" + v.getName() + "' holds a secret ($@ reaches $@) but is not cleared on every path before " +
    v.getFunction().getName() + " returns.", use, use.toString(), consumer,
  consumer.getTarget().getName()
