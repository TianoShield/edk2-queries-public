/**
 * @name BaseLib string model properties
 * @description Lists every (function, category, detail) triple produced by the
 *              ArrayFunction models in BaseLibString.qll.  Used as a
 *              regression test: run with `--learn` to accept output as baseline,
 *              then re-run to detect drift.
 * @kind table
 */

import cpp
import semmle.code.cpp.models.interfaces.ArrayFunction
import lib.MdePkg.BaseLibString

/**
 * Holds if `f` is an EDK2 string function declared in test.c.
 */
private predicate edk2TestFunc(Function f) { f.getFile().getBaseName() = "test.c" }

/**
 * Relation collecting ALL modelled ArrayFunction properties into one
 * normalised form: (funcName, category, detail)
 */
private predicate edk2Prop(string funcName, string category, string detail) {
  exists(ArrayFunction f, int param |
    edk2TestFunc(f) and funcName = f.getName()
  |
    f.hasArrayInput(param) and category = "arrayInput" and detail = param.toString()
    or
    f.hasArrayOutput(param) and category = "arrayOutput" and detail = param.toString()
    or
    f.hasArrayWithNullTerminator(param) and category = "nullTerminator" and detail = param.toString()
    or
    exists(int cp |
      f.hasArrayWithVariableSize(param, cp) and
      category = "variableSize" and
      detail = "buf=" + param + ",count=" + cp
    )
    or
    f.hasArrayWithUnknownSize(param) and category = "unknownSize" and detail = param.toString()
  )
}

from string funcName, string category, string detail
where edk2Prop(funcName, category, detail)
select funcName, category, detail
order by funcName, category, detail
