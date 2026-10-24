/**
 * Shared TaintFunction models for functions defined in
 * MdePkg/Library/BaseLib/LinkedList.c.
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint

/**
 * Models:
 *
 * `VOID InsertTailList(LIST_ENTRY *List, LIST_ENTRY *Entry)`
 *
 * `InsertTailList` mutates `List` to contain `Entry`. In EDK2 HTTP/TLS code the
 * inserted entry is commonly `&Nbuf->List`, so taint on the inserted list entry
 * (`arg[*1]`) should flow to the mutated list head (`arg[*0]`).
 */
class InsertTailListTaintFunction extends Function, TaintFunction {
  InsertTailListTaintFunction() { this.hasGlobalName("InsertTailList") }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(1) and
    output.isParameterDeref(0)
  }
}
