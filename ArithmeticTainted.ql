/**
 * @name User-controlled data in arithmetic expression
 * @description Arithmetic operations on user-controlled data that is
 *              not validated can cause overflows.
 *              Catches CVE-2025-2295
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.6
 * @precision low
 * @id cpp/tainted-arithmetic
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 */

import cpp
import semmle.code.cpp.security.Overflow
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance as Dominance
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.security.FlowSources as FS
import lib.Edk2
import Flow::PathGraph

/**
 * Holds if `op` is part of, or dominated by, a recognized overflow-check
 * idiom: an EDK2- or C-standard "headroom" guard
 * ([[hasOverflowHeadroomGuard]]) or the BaseSafeIntLib `(a+b) cmp a`
 * post-check pattern ([[isUnsignedOverflowPostCheck]]).
 *
 * `op` is an `Expr` rather than an `Operation` so the same guard idioms apply
 * to a BaseLib multiply-wrapper call site treated as a multiplication (see
 * [[isSink]]): e.g. `if (x < MAX_UINT64 / 512) MultU64x32 (x, 512);` is
 * recognized as a headroom-guarded call.
 */
predicate hasOverflowGuard(Expr op) {
  hasOverflowHeadroomGuard(op) or isUnsignedOverflowPostCheck(op)
}

/**
 * Holds if arithmetic operation `op` on operand `e` lacks a guard against
 * `effect`.
 *
 * The overflow case has two branches: the standard
 * [[missingGuardAgainstOverflow]] and the EDK2 supplement
 * [[missingGuardAgainstOverflowForUnmodeledOperand]] for operand shapes the
 * standard check ignores. Both branches must drop `op` when an EDK2/C overflow
 * idiom guards it
 * (`not hasOverflowGuard(op)`) — the standard check does not recognize the
 * `MAX_*` headroom or BaseSafeIntLib `(a+b) cmp a` post-check forms, and the
 * post-check additions are plain `VariableAccess` operands that flow through the
 * standard branch, so the guard cannot live only in the supplement.
 *
 * The underflow case handles binary subtraction, compound subtraction, and
 * decrement through [[unguardedSubtractionUnderflow]]. The standard
 * [[missingGuardAgainstUnderflow]] remains for other operation shapes such as
 * multiplication; its broad plain-`VariableAccess` handling of these three
 * subtraction shapes is excluded as too imprecise.
 */
bindingset[op]
predicate missingGuard(Operation op, Expr e, string effect) {
  effect = "underflow" and
  (
    unguardedSubtractionUnderflow(op, e)
    or
    missingGuardAgainstUnderflow(op, e) and
    not op instanceof SubExpr and
    not op instanceof AssignSubExpr and
    not op instanceof DecrementOperation
  )
  or
  effect = "overflow" and
  (
    missingGuardAgainstOverflow(op, e) and not hasOverflowGuard(op)
    or
    missingGuardAgainstOverflowForUnmodeledOperand(op, e)
  )
}

/**
 * Holds if `op`'s result, or that of an enclosing operation it feeds, may
 * overflow its result type after conversions (`convertedExprMightOverflow*`,
 * which is cast-aware: it accounts for both a same-type wrap and a narrowing
 * conversion the value exceeds).
 *
 * This is the CVE-2023-45232/45233 signal: the IP6 extension-header parser
 * stores option lengths and offsets back into `UINT8`s
 * (`OptionLen = (UINT8)((*Option + 1) * 8 - 2)`,
 * `Offset = (UINT8)(Offset + *(Option + Offset + 1) + 2)`), so an
 * attacker-sized field overflows the 8-bit result and breaks the parse loop.
 * The upstream fix widens those locals to `UINT16` / `UINT32`: the same
 * expressions (max 2046) then fit their result type, no enclosing operation can
 * overflow, this predicate is `false`, and the patched code is not flagged.
 *
 * The enclosing-operation search recovers overflows that sit above the flagged
 * operand's immediate operation, e.g. the `(UINT8)` cast on the `... - 2`
 * subtraction enclosing `(*Option + 1) * 8`, or the `(UINT16)` cast on the
 * `& ~0x7` enclosing CVE-2022-36765's `HobLength + 0x7`. It must NOT require a
 * narrowing conversion specifically: same-type accumulator wraps such as
 * `Num = Num * 10 + (*String - '0')` (`Mtftp4Option.c`) overflow `Num`'s own
 * type without any narrowing, and are genuine bugs to keep.
 */
predicate feedsOverflowingOperation(Operation op) {
  exists(Operation anc |
    anc = op.getParent*() and
    (
      convertedExprMightOverflowPositively(anc) or
      convertedExprMightOverflowNegatively(anc)
    ) and
    not hasOverflowGuard(anc)
  )
}

/**
 * Holds if `op` is a positive-overflow-direction integer operation: an
 * addition, increment, or multiplication (with their compound-assignment
 * forms). Subtraction / decrement underflow is reported separately
 * (see [[unguardedSubtractionUnderflow]]); without this restriction the
 * operand-shape test below — which is op-type-agnostic — would report those as
 * overflows.
 */
predicate isPositiveOverflowOperation(Operation op) {
  op instanceof AddExpr or
  op instanceof AssignAddExpr or
  op instanceof IncrementOperation or
  op instanceof MulExpr or
  op instanceof AssignMulExpr
}

/**
 * Holds if `e` is an operand shape the standard [[missingGuardAgainstOverflow]]
 * does not model: it flags only an operand whose target is a (≥`int`-width)
 * `LocalScopeVariable`. The shapes it misses are
 *  - a struct-field read (a `FieldAccess`'s target is a `Field`, not a local),
 *  - a dereference / call result / sub-expression (not a `VariableAccess`), and
 *  - a sub-`int` local, whose operands `int`-promote so its immediate operation
 *    cannot overflow `int` — the overflow, if any, is at an enclosing narrowing
 *    cast (e.g. CVE-2022-36765's `(UINT16)((HobLength + 0x7) & ~0x7)`).
 */
predicate operandShapeMissedByStandardOverflowCheck(Expr e) {
  e instanceof FieldAccess
  or
  not e instanceof VariableAccess
  or
  e.(VariableAccess).getTarget().getUnspecifiedType().(IntegralType).getSize() <
    any(IntType it).getSize()
}

/**
 * Holds if `op` is a multiplication whose product type is wider than `int`
 * (a 64-bit `UINTN` / `UINT64` result). Every such product reachable here has
 * factors of at most `UINT32` magnitude — a `UINT32` field, a loop index
 * bounded by the `UINT32` `NumberOfPartitionEntries`, or a small `sizeof (...)`
 * constant — so it is at most `(2^32 - 1)^2 < 2^64` and cannot overflow
 * `UINT64`. Used to drop the GPT/TPM partition-walk offsets
 * `Index * SizeOfPartitionEntry` (`Gpt.c`, `DxeTpm*MeasureBootLib.c`) and
 * division-then-multiplication expressions whose factors have the same bounds.
 * Genuine 64-bit overflows go through the `MultU64x*` intrinsics (reported at
 * the call site); CVE-2022-36763's `UINT32 * UINT32` keeps a `≤ int` product
 * and is still flagged. (Keyed on product width, so a wide product from a
 * genuinely `UINT64`-ranged operand is also dropped.)
 */
predicate wideMultiplicationWithBoundedFactors(Operation op) {
  op instanceof MulExpr and op.getType().getSize() > any(IntType it).getSize()
}

/**
 * Holds if `op` is an unguarded overflow-prone integer operation on an operand
 * `e` whose shape the standard [[missingGuardAgainstOverflow]] does not model
 * ([[operandShapeMissedByStandardOverflowCheck]]).
 *
 * `feedsOverflowingOperation(op)` is the precision gate: the operand is reported
 * only when `op` (or an operation it feeds) can actually overflow. It keeps the
 * real bugs — CVE-2022-36763's `UINT32 * UINT32` (overflows its own type),
 * CVE-2022-36765's `(UINT16)(...)` truncation, the CVE-2023-45232/45233
 * `(UINT8)` option-length math — while dropping arithmetic that is computed in a
 * wide-enough type to hold it: `DataLen + 4` (`UINT16` `int`-promoted),
 * `(UINT32)Length * 8` (widened before the multiply), and the
 * CVE-2023-45232/45233 fix's `UINT16`-widened siblings.
 */
bindingset[op]
predicate missingGuardAgainstOverflowForUnmodeledOperand(Operation op, Expr e) {
  isPositiveOverflowOperation(op) and
  operandShapeMissedByStandardOverflowCheck(e) and
  feedsOverflowingOperation(op) and
  not wideMultiplicationWithBoundedFactors(op) and
  // Drop when an EDK2/C "headroom" guard or BaseSafeIntLib `(a+b) cmp a`
  // post-check dominates `op` (e.g. CVE-2022-36765's `HobLength > MAX_UINT16 - 0x7`).
  not hasOverflowGuard(op)
}

/**
 * Holds if `e` is a pointer difference (`p - q`). Uses
 * `getFullyConverted().getUnconverted()` so a wrapping cast
 * (`(INTN)(cursor - base)`) does not hide it.
 *
 * Precision heuristic for the underflow sink below: cursor length fixups
 * (`(writeCursor - base) - header-size`, e.g. `Dhcp6AppendIaOption` in
 * `Dhcp6Utility.c`) match that sink's shape but are FP-prone, not the parsed
 * scalar lengths (`NTOHS(option-len) - header-size`) it targets.
 */
private predicate isPointerDifferenceMinuend(Expr e) {
  e.getFullyConverted().getUnconverted() instanceof PointerDiffExpr
}

/**
 * Holds if `op` is a binary subtraction `minuend - subtrahend` or a compound
 * subtraction `minuend -= subtrahend`. (A decrement `e--` is handled separately
 * in [[unguardedSubtractionUnderflow]]: its subtrahend is the constant 1.)
 */
private predicate subtractionOperands(Operation op, Expr minuend, Expr subtrahend) {
  minuend = op.(SubExpr).getLeftOperand() and subtrahend = op.(SubExpr).getRightOperand()
  or
  minuend = op.(AssignSubExpr).getLValue() and subtrahend = op.(AssignSubExpr).getRValue()
}

/** Holds if `e` is unsigned or range analysis proves that it is non-negative. */
private predicate isNonNegativeTerm(Expr e) {
  e.getUnspecifiedType().(IntegralType).isUnsigned()
  or
  lowerBound(e.getFullyConverted()) >= 0
}

/**
 * Holds if `total` is `term` plus zero or more non-negative addends. The base
 * case matches `total` and `term` by global value number. For an addition, the
 * predicate recursively finds `term` in either operand and requires the other
 * operand to satisfy [[isNonNegativeTerm]]. Thus, in mathematical integer
 * arithmetic, `total` is at least `term`.
 *
 * This predicate checks the added terms, not whether the additions can overflow.
 * For example, it accepts `Amount + (UINT32)-1` even though that expression can
 * wrap below `Amount`. Such an unchecked addition is a separate CWE-190 sink;
 * rejecting it here would also reject legitimate guard bounds such as
 * `CertSize + SumOfBytesHashed` and reintroduce stable-tree false positives.
 */
private predicate sumContainsTerm(Expr total, Expr term) {
  globalValueNumber(total) = globalValueNumber(term)
  or
  exists(AddExpr add | add = total |
    sumContainsTerm(add.getLeftOperand(), term) and isNonNegativeTerm(add.getRightOperand())
    or
    sumContainsTerm(add.getRightOperand(), term) and isNonNegativeTerm(add.getLeftOperand())
  )
}

/**
 * Holds if a `GuardCondition` dominating `op` proves `hi >= lo` (both matched to
 * the guard's operands by global value number, so field / dereference operands
 * `SimpleRangeAnalysis` cannot bound are still cleared). Both `ensuresLt`
 * polarities are read, mirroring [[hasConstantLowerBound]]. `ensuresLt(a, b, k)` is
 * `a < b + k`; false means `a >= b + k`:
 *  - `hi < lo + k` false on the path to `op`  =>  hi >= lo + k, so hi >= lo  (k >= 0);
 *  - `lo < hi + k` true  on the path to `op`  =>  hi >= lo - k + 1, so hi >= lo  (k <= 1).
 */
private predicate guardProvesGe(Operation op, Expr hi, Expr lo) {
  exists(GuardCondition g, Expr gHi, Expr gLo, int k |
    globalValueNumber(gHi) = globalValueNumber(hi) and
    globalValueNumber(gLo) = globalValueNumber(lo)
  |
    g.ensuresLt(gHi, gLo, k, op.getBasicBlock(), false) and k >= 0
    or
    g.ensuresLt(gLo, gHi, k, op.getBasicBlock(), true) and k <= 1
  )
}

/**
 * Holds if a dominating guard proves `minuend >= subtrahend` for a *non-constant*
 * subtrahend, so `minuend - subtrahend` cannot go below zero. Two shapes:
 *
 *  - direct/summed: a guard proves `minuend >= boundSum` where `boundSum` is the
 *    subtrahend or an (unsigned) sum containing it — the extra terms only raise
 *    bound. For example, `if (mImageSize > CertSize + SumOfBytesHashed)` proves
 *    that `mImageSize - CertSize` cannot underflow.
 *  - chained: the minuend is itself `M - A`, and a guard proves
 *    `M >= (A + subtrahend)`, so `(M - A) >= subtrahend` — the outer step of the
 *    guarded `mImageSize - CertSize - SumOfBytesHashed` hash-range subtraction.
 */
private predicate hasMinuendGeSubtrahendGuard(Operation op, Expr minuend, Expr subtrahend) {
  exists(Expr boundSum |
    sumContainsTerm(boundSum, subtrahend) and guardProvesGe(op, minuend, boundSum)
  )
  or
  exists(Expr boundSum |
    sumContainsTerm(boundSum, minuend.(SubExpr).getRightOperand()) and
    sumContainsTerm(boundSum, subtrahend) and
    guardProvesGe(op, minuend.(SubExpr).getLeftOperand(), boundSum)
  )
}

/**
 * Holds if a dominating guard proves the subtraction `op` (`minuend - subtrahend`)
 * cannot underflow: a positive-constant subtrahend cleared by the lower-bound
 * machinery ([[hasConstantLowerBound]] — relational or digit-class), or a
 * non-constant subtrahend cleared by a `minuend >= subtrahend` guard
 * ([[hasMinuendGeSubtrahendGuard]]).
 */
private predicate hasSubtractionUnderflowGuard(Operation op, Expr minuend, Expr subtrahend) {
  hasConstantLowerBound(op, minuend, subtrahend.getValue().toInt())
  or
  hasMinuendGeSubtrahendGuard(op, minuend, subtrahend)
}

/**
 * Holds if `op` is an unsigned subtraction that may go below zero — so the sign
 * flip becomes a huge length / count — with `e` the attacker-influenced operand
 * to flag and no dominating guard establishing that the minuend is at least the
 * subtrahend. Either operand may carry the taint: an over-small minuend or an
 * over-large subtrahend both drive the difference negative, so `e` ranges over
 * the minuend (unless it is a pointer difference — [[isPointerDifferenceMinuend]]
 * — an FP-prone shape) and the subtrahend. Three operation shapes:
 *
 *  - binary `a - b`   (`SubExpr`),
 *  - compound `a -= b` (`AssignSubExpr`), and
 *  - decrement `a--`   (`DecrementOperation`, subtrahend the constant 1, so only
 *    the minuend can be attacker-influenced).
 *
 * CVE-2023-45229 (binary, minuend) — a fixed header size subtracted from a
 * packet-parsed length with no minimum-size check:
 * `IaInnerLen = (UINT16)(NTOHS (option-len) - 12)` wraps when the length `< 12`.
 *
 * Precision comes from a real guard check rather than the result width.
 * `convertedExprMightOverflowNegatively` already clears bounds
 * `SimpleRangeAnalysis` proves for local operands; the guard predicates
 * additionally clear bounds on field / dereference operands range analysis
 * cannot track — e.g. `RelocDir->Size - 1` under `if (RelocDir->Size > 0)`, the
 * SafeString `c - '0'` decode under its digit-class check, and the guarded
 * PE/COFF hash range `mImageSize - CertSize - SumOfBytesHashed` under
 * `if (mImageSize > CertSize + SumOfBytesHashed)`.
 */
predicate unguardedSubtractionUnderflow(Operation op, Expr e) {
  convertedExprMightOverflowNegatively(op) and
  // The result is reinterpreted as unsigned, so a sign flip becomes a huge value.
  op.getFullyConverted().getUnspecifiedType().(IntegralType).isUnsigned() and
  (
    exists(Expr minuend, Expr subtrahend |
      subtractionOperands(op, minuend, subtrahend) and
      not hasSubtractionUnderflowGuard(op, minuend, subtrahend)
    |
      // Report whichever operand the taint reaches: an over-small minuend or an
      // over-large subtrahend both cause the underflow.
      e = minuend and not isPointerDifferenceMinuend(minuend)
      or
      e = subtrahend
    )
    or
    // Decrement: subtrahend is the constant 1, so only the minuend applies.
    e = op.(DecrementOperation).getOperand() and
    not hasConstantLowerBound(op, e, 1)
  )
}

/**
 * Holds if a guard dominating `op` proves the minuend `e` is at least
 * `subtrahend`, so `e - subtrahend` cannot go below zero.
 *
 * The minuend is matched to the value the guard bounds by global value number
 * rather than by syntactic identity, so this clears lower-bound checks on field
 * and dereference operands — e.g. `if (RelocDir->Size > 0) { ...
 * RelocDir->Size - 1 ... }` — that `SimpleRangeAnalysis` (and hence
 * `convertedExprMightOverflowNegatively`) cannot track. Two guard shapes:
 *
 *  - a relational `GuardCondition` (`ensuresLt`), where the constant `k` absorbs
 *    the off-by-one between the guard's threshold and the subtrahend;
 *  - a digit/hex character-class predicate call
 *    (`InternalAsciiIsDecimalDigitCharacter` and its Ascii/hex/CHAR16 variants),
 *    which constrains its argument to a digit character and hence to `>= '0'`
 *    (0x30) — clearing the SafeString `c - '0'` decode, whose lower bound comes
 *    from a call rather than a comparison `ensuresLt` could read.
 */
bindingset[subtrahend]
predicate hasConstantLowerBound(Operation op, Expr e, int subtrahend) {
  exists(GuardCondition g, Expr bound, Expr guarded, int k |
    globalValueNumber(guarded) = globalValueNumber(e)
  |
    // `bound < guarded + k` holds in `op`'s block  =>  guarded >= bound - k + 1.
    g.ensuresLt(bound, guarded, k, op.getBasicBlock(), true) and
    bound.getValue().toInt() - k + 1 >= subtrahend
    or
    // `guarded < bound + k` is false in `op`'s block  =>  guarded >= bound + k.
    g.ensuresLt(guarded, bound, k, op.getBasicBlock(), false) and
    bound.getValue().toInt() + k >= subtrahend
  )
  or
  // A dominating digit/hex character-class predicate
  // ([[Edk2DigitCharacterClassFunction]]) constrains its argument to a digit,
  // hence to `>= '0'` (48); so `e - subtrahend` cannot go negative when
  // `subtrahend <= '0'`. The checked character and the minuend are matched
  // structurally (same dereferenced variable) rather than by value number:
  // they are distinct memory loads that GVN does not relate across the
  // intervening stores of a parse loop (`*Data = *Data * 10 + (*String - '0')`).
  subtrahend <= 48 and
  exists(GuardCondition g, FunctionCall classCheck |
    g = classCheck and
    classCheck.getTarget() instanceof Edk2DigitCharacterClassFunction and
    g.controls(op.getBasicBlock(), true) and
    sameDereferencedVariable(classCheck.getArgument(0), e)
  )
}

/** Holds if `a` and `b` read the same variable, directly or through one dereference. */
private predicate sameDereferencedVariable(Expr a, Expr b) {
  exists(Variable v |
    a.(VariableAccess).getTarget() = v and b.(VariableAccess).getTarget() = v
    or
    a.(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = v and
    b.(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = v
  )
}

/** Gets a configured flow source and its user-facing provenance string. */
predicate isSource(FS::FlowSource source, string sourceType) { sourceType = source.getSourceType() }

/**
 * Holds if `name` is a C / EDK2 max-value-limit macro: the EDK2 `MAX_*`
 * family (`MAX_ADDRESS`, `MAX_UINTN`, `MAX_UINT32`, ...) or the standard
 * `<limits.h>` / `<stdint.h>` `*_MAX` family (`UINT_MAX`, `SIZE_MAX`, ...).
 */
bindingset[name]
predicate isMaxMacroName(string name) {
  name.regexpMatch("MAX_(ADDRESS|U?INTN|U?INT(8|16|32|64))" +
      "|((U?|S)CHAR|U?SHRT|U?INT|U?LONG|U?LLONG|SIZE|PTRDIFF|U?INT(8|16|32|64|PTR|MAX))_MAX")
}

/**
 * Holds if `e` spells the maximum value of an unsigned integer type. Two
 * shapes:
 *  - a `MAX_*` / `*_MAX` macro invocation (see [[isMaxMacroName]]);
 *  - the EDK2 hand-rolled equivalent `(<unsigned>)(~0)` / `(<unsigned>)-1`
 *    — a cast to an unsigned integer type whose operand has constant
 *    value `-1`. `BasePeCoff.c` overflow-headroom guards predate the
 *    `MAX_*` macros and still use this form:
 *
 *        if ((UINT32)(~0) - SectionHeader.PointerToRawData
 *                              < SectionHeader.SizeOfRawData) { ... }
 */
predicate isUnsignedMaxExpr(Expr e) {
  exists(MacroInvocation mi |
    isMaxMacroName(mi.getMacroName()) and
    e = mi.getExpr()
  )
  or
  exists(Cast cast |
    cast = e and
    cast.getType().getUnspecifiedType().(IntegralType).isUnsigned() and
    cast.getExpr().getValue() = "-1"
  )
}

/**
 * Holds if `op` participates in a max-value "headroom" bounds check, in
 * either of two forms.
 *
 * **Form 1 — guard-dominated.** `op`'s basic block is controlled by a
 * `GuardCondition` whose AST contains an unsigned-max expression (a
 * `MAX_*` macro or the `(<unsigned>)(~0)` idiom; see
 * [[isUnsignedMaxExpr]]). `op` only runs once that guard has established
 * the bound, so it is treated as safe. Examples:
 *
 *     // EDK2 SafeString safe-decimal accumulator
 *     if (*Data > ((MAX_UINTN - (*String - '0')) / 10)) return ERROR;
 *     *Data = *Data * 10 + (*String - '0');                 // suppressed
 *
 *     // openssl `<limits.h>` equivalent
 *     if (res > (LONG_MAX - d) / 10L) return 0;
 *     res = res * 10 + d;                                   // suppressed
 *
 *     // guard tests the safe condition; body runs only when it holds
 *     if (Size - 1 < MAX_UINT32 - VirtualAddress) {
 *       sum = VirtualAddress + Size - 1;                    // suppressed
 *     }
 *
 *     // BasePeCoff legacy `(UINT32)(~0)` form of the same guard
 *     if ((UINT32)(~0) - PointerToRawData < SizeOfRawData) return ERROR;
 *     last = PointerToRawData + SizeOfRawData - 1;          // suppressed
 *
 * Both polarities are matched: guards that early-return on the unsafe
 * condition (first, second, fourth examples) and guards whose body runs
 * only when the safe condition holds (third example).
 *
 * **Form 2 — self-referential.** `op` is itself an ancestor of an
 * unsigned-max expression: the arithmetic *is* the bounds calculation.
 * EDK2's `MemoryAllocationLib.c` allocation ASSERTs are the canonical case:
 *
 *     ASSERT (AllocationSize <= (MAX_ADDRESS - (UINTN)Buffer + 1));
 *     //                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *     //                       the `+ 1` AddExpr is the flagged operation
 *
 * The `+ 1` lives inside the check expression rather than in a block
 * dominated by it, so Form 1 cannot match. Anything in the AST subtree of
 * an unsigned-max expression is part of a bounds calculation, not a
 * vulnerable operand.
 */
predicate hasOverflowHeadroomGuard(Expr op) {
  // Form 1: op is dominated by a guard that mentions an unsigned-max value.
  exists(GuardCondition guard, Expr maxExpr |
    guard.controls(op.getBasicBlock(), _) and
    isUnsignedMaxExpr(maxExpr) and
    maxExpr.getEnclosingElement*() = guard
  )
  or
  // Form 2: op encloses an unsigned-max value — it is itself the bounds expr.
  exists(Expr maxExpr |
    isUnsignedMaxExpr(maxExpr) and
    maxExpr.getEnclosingElement+() = op
  )
}

/**
 * Holds if `add` is the addition inside an unsigned overflow post-check that
 * compares the wrapped sum back against one of its own operands, e.g.
 * `(a + b) >= a` or `(a + b) < a`. The addition itself is the wrap-detector,
 * so its unsigned overflow is intentional rather than a bug.
 */
predicate isUnsignedOverflowPostCheckAdd(AddExpr add) {
  exists(RelationalOperation cmp, VariableAccess other, Variable v |
    cmp.hasOperands(add, other) and
    other.getTarget() = v and
    add.getAnOperand().(VariableAccess).getTarget() = v
  )
}

/** Holds if `a` and `b` are additions over the same pair of variables (any order). */
predicate sameAddOperandVars(AddExpr a, AddExpr b) {
  exists(Variable v1, Variable v2 |
    a.getLeftOperand().(VariableAccess).getTarget() = v1 and
    a.getRightOperand().(VariableAccess).getTarget() = v2
  |
    b.getLeftOperand().(VariableAccess).getTarget() = v1 and
    b.getRightOperand().(VariableAccess).getTarget() = v2
    or
    b.getLeftOperand().(VariableAccess).getTarget() = v2 and
    b.getRightOperand().(VariableAccess).getTarget() = v1
  )
}

/**
 * Holds if `op` is part of the unsigned overflow post-check idiom used in
 * `MdePkg/Library/BaseSafeIntLib`:
 *
 *     if ((Augend + Addend) >= Augend) { *Result = Augend + Addend; ... }
 *
 * Either `op` is the wrap-detecting addition itself (operand of `(a+b) cmp a`)
 * or `op` is an addition over the same variables that is controlled by such
 * a check.
 */
predicate isUnsignedOverflowPostCheck(Expr op) {
  exists(AddExpr add | add = op |
    isUnsignedOverflowPostCheckAdd(add)
    or
    exists(GuardCondition guard, AddExpr checkAdd |
      guard.controls(add.getBasicBlock(), _) and
      checkAdd.getEnclosingElement*() = guard and
      isUnsignedOverflowPostCheckAdd(checkAdd) and
      sameAddOperandVars(add, checkAdd)
    )
  )
}

/**
 * Holds if `factor` is a factor argument of the multiply-wrapper `call` that is
 * a field of an `EFI_PARTITION_TABLE_HEADER` already validated by a successful
 * `*SanitizeEfiPartitionTableHeader` call dominating `call`.
 *
 * The sanitizer bounds that field against `MAX_UINT64` (see
 * [[Edk2PartitionTableHeaderSanitizer]]), and the wrapper's product is 64-bit,
 * so the multiplication cannot overflow — the call site is not a real bug. The
 * suppression is deliberately scoped to the 64-bit wrapper sink: it must NOT
 * extend to the UINT32 `NumberOfPartitionEntries * SizeOfPartitionEntry` of
 * CVE-2022-36763, which a `MAX_UINT64` bound does not make safe.
 */
predicate edk2MultiplyFactorSanitized(Edk2MultiplyCall call, Expr factor) {
  factor = call.getAFactorArgument() and
  exists(Edk2PartitionTableHeaderSanitizerCall sanitize, Variable header |
    sanitize.getHeaderPointer().(VariableAccess).getTarget() = header and
    factor.(FieldAccess).getQualifier().(VariableAccess).getTarget() = header and
    // The sanitizer call gates all subsequent use (it is only ever called in an
    // `if (EFI_ERROR (...)) return;` guard), so its dominating the multiply
    // means the header field reaching `factor` has been validated.
    Dominance::dominates(sanitize, call)
  )
}

/**
 * Holds if `reported` is the expression to flag for an alert reaching `sink`,
 * with overflow/underflow direction `effect`.
 *
 * Two sink shapes:
 *  - `reported` is an operand of an unguarded integer addition, increment,
 *    multiplication, subtraction, compound subtraction, or decrement (whatever
 *    [[missingGuard]] flags for the direction `effect`). Multiplication covers
 *    the `NumberOfPartitionEntries * SizeOfPartitionEntry` overflow of
 *    CVE-2022-36763: the flagged operand is a field-access load upstream of the
 *    multiply, so the "both operands non-constant" barrier (which removes the
 *    multiply *result* node) does not suppress it. Subtraction / compound
 *    subtraction / decrement cover depleting-length underflows such as the
 *    CVE-2023-45229 `(UINT16)(NTOHS (option-len) - 12)`, for which
 *    [[missingGuard]] uses only [[unguardedSubtractionUnderflow]], not the broad
 *    standard check.
 *    Multiplications inside a BaseLib `InternalMath*` helper are excluded here
 *    and reported at their wrapper's call site instead (next case).
 *  - `reported` is a factor argument of an EDK2 BaseLib fixed-width multiply
 *    helper call (`MultU64x32`, `MultU64x64`, `MultS64x64`). The multiply
 *    itself lives in the BaseLib `InternalMath*` implementation, so surfacing
 *    the overflow at the call site points the alert at the caller rather than
 *    into library code. The call is treated as a multiplication whose operands
 *    are its factor arguments: the fixed-width product can always overflow, so
 *    it is reported unless [[hasOverflowGuard]] recognizes an overflow guard
 *    dominating the call (the call-site analogue of [[missingGuard]]'s
 *    `not hasOverflowGuard`; see [[Edk2MultiplyCall]]) or the factor is a
 *    header field already bounded by a dominating partition-table sanitizer
 *    ([[edk2MultiplyFactorSanitized]]).
 */
predicate isSink(DataFlow::Node sink, Expr reported, string effect) {
  exists(Operation op |
    reported = sink.asExpr() and
    missingGuard(op, reported, effect) and
    op.getAnOperand() = reported and
    (
      op instanceof AddExpr or
      op instanceof IncrementOperation or
      op instanceof MulExpr or
      op instanceof SubExpr or
      op instanceof AssignSubExpr or
      op instanceof DecrementOperation
    ) and
    not op.getEnclosingFunction() instanceof Edk2InternalMultiplyFunction
  )
  or
  exists(Edk2MultiplyCall call |
    reported = sink.asExpr() and
    reported = call.getAFactorArgument() and
    effect = "overflow" and
    not hasOverflowGuard(call) and
    not edk2MultiplyFactorSanitized(call, reported)
  )
}

/**
 * Holds if `var` appears on the *lesser* side of a non-zero relational check,
 * which acts as a coarse upper-bound check on `var`.
 *
 * Only the lesser-side position counts. In `FreeMemory < HobLength`,
 * `HobLength` is the greater operand and the comparison bounds `FreeMemory`,
 * not `HobLength` — treating that pattern as a bounds check on the greater
 * operand wrongly suppresses CVE-2022-36765-style overflows where the
 * caller-supplied length flows into `HobLength + 0x7` *before* the
 * comparison.
 */
predicate hasUpperBoundsCheck(Variable var) {
  exists(RelationalOperation oper, VariableAccess access |
    oper.getLesserOperand() = access and
    access.getTarget() = var and
    // Comparing to 0 is not an upper bound check
    not oper.getAnOperand().getValue() = "0"
  )
}

/** Holds if `instr` is a constant or a unary expression over a constant. */
predicate constantInstruction(Instruction instr) {
  instr instanceof ConstantInstruction or
  constantInstruction(instr.(UnaryInstruction).getUnary())
}

/** Holds if `load` reads the local variable `var`. */
predicate readsVariable(LoadInstruction load, Variable var) {
  load.getSourceAddress().(VariableAddressInstruction).getAstVariable() = var
}

/**
 * Holds if `node` is guarded by an equality check against `checkedVar`.
 */
predicate nodeIsBarrierEqualityCandidate(DataFlow::Node node, Operand access, Variable checkedVar) {
  exists(Instruction instr | instr = node.asInstruction() |
    readsVariable(instr, checkedVar) and
    any(IRGuardCondition guard).ensuresEq(access, _, _, instr.getBlock(), true)
  )
}

module Config implements DataFlow::ConfigSig {
  /** Holds if `source` is one of the configured remote input sources. */
  predicate isSource(DataFlow::Node source) { isSource(source, _) }

  /** Holds if `sink` is an operand of an unguarded integer addition. */
  predicate isSink(DataFlow::Node sink) { isSink(sink, _, _) }

  /** Holds if `node` is known to block unsafe arithmetic flow. */
  predicate isBarrier(DataFlow::Node node) {
    // Third-party OpenSSL code is out of scope; block all flow through it.
    isOpensslNode(node)
    or
    // Attacker-controlled length reaching a BaseMemoryLib block function
    // (`CopyMem`, `CompareMem`, `SetMem*`, `ZeroMem`, `ScanMem*`, ...) is the
    // concern of TaintedBaseMemoryLibLength.ql. Barrier the function's own
    // `Length` *parameter* (inside the callee) so the length does not resurface
    // as arithmetic in the library implementation's `(UINTN)Buffer + Length` /
    // `(Length - 1)` bounds math. Barriering the callee parameter, not the
    // call-site argument, keeps the argument value live in the caller: if that
    // same value also feeds an arithmetic operation in the caller's own code,
    // this query still flags that operation, as its own alert at the caller's
    // arithmetic.
    isBaseMemoryLibLengthParameter(node.asParameter())
    or
    exists(StoreInstruction store, Expr e |
      store = node.asInstruction() and e = node.asCertainDefinition()
    |
      // Block flow to "small types"
      store.getResultType().getUnspecifiedType().(IntegralType).getSize() <= 1
    )
    or
    // Block flow if there's an upper bound check of the variable anywhere in the program
    exists(Variable checkedVar, Instruction instr | instr = node.asInstruction() |
      readsVariable(instr, checkedVar) and
      hasUpperBoundsCheck(checkedVar)
    )
    or
    // Block flow if the node is guarded by an equality check
    exists(Variable checkedVar, Operand access |
      nodeIsBarrierEqualityCandidate(node, access, checkedVar) and
      readsVariable(access.getDef(), checkedVar)
    )
    or
    // Block flow into DXE core allocator/free call sites. Arithmetic below
    // these calls operates on bookkeeping ranges, not user-controlled data.
    isDxeCoreFreeArgument(node)
    or
    isDxeCoreAllocateArgument(node)
    or
    // Block flow to any binary instruction whose operands are both non-constants.
    exists(BinaryInstruction iTo |
      iTo = node.asInstruction() and
      not constantInstruction(iTo.getLeft()) and
      not constantInstruction(iTo.getRight()) and
      // propagate taint from either the pointer or the offset, regardless of constantness
      not iTo instanceof PointerArithmeticInstruction and
      // Let byte-order assembly (`NTOH24 (src) = (src[0]<<16)|(src[1]<<8)|src[2]`
      // and similar macros) carry taint. The OR reconstructs one attacker value
      // from its own bytes, so it is a first-order taint carrier, not the
      // second-order composite of two independent values this barrier targets.
      // Without this, taint dies inside `ISCSI_GET_DATASEG_LEN`, hiding the
      // CVE-2024-38805 `IScsiBuildKeyValueList` `Len--` underflow.
      not isByteOrderAssemblyOr(iTo.getUnconvertedResultExpression())
    )
  }

  /**
   * Additional taint flow steps that bridge gaps the standard library and the
   * shared content models do not cover on their own:
   *
   *   - `fpdtAddressOfFieldIndirectStep`: the EDK2 `Sub = &Parent->Field`
   *     pattern that propagates taint on a `S3_PERFORMANCE_TABLE *` into the
   *     content of pointers derived via address-of-field on the FPDT S3
   *     struct family.
   *   - `peCoffLoaderReadFileBufferStep`: at every PE_COFF_LOADER_READ_FILE
   *     call site, links the bytes loaded into the Buffer argument back to
   *     the PE_COFF_LOADER_IMAGE_CONTEXT struct whose `ImageAddress` field
   *     the Buffer expression dereferences.
   *   - `peCoffLoaderImageContextFieldWriteStep`: function-local bridge
   *     from `ImageContext->ImageAddress` reads to indirect reads through
   *     reinterpret-cast image-header pointers.
   *   - `efiImageSectionHeaderMiscUnionStep`: routes taint across the
   *     `EFI_IMAGE_SECTION_HEADER.Misc` anonymous union, which two
   *     consecutive `TaintInheritingContent` reads do not always compose
   *     through.
   *   - `netbufCopyDestObjectStep`: taints the packet object that a
   *     `NetbufCopy` flattens a received `NET_BUF` into, across the
   *     `&Packet->Field` destination alias the library does not bridge.
   */
  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    fpdtAddressOfFieldIndirectStep(node1, node2)
    or
    peCoffLoaderReadFileBufferStep(node1, node2)
    or
    peCoffLoaderImageContextFieldWriteStep(node1, node2)
    or
    efiImageSectionHeaderMiscUnionStep(node1, node2)
    or
    netbufCopyDestObjectStep(node1, node2)
  }

  /** Enables diff-informed incremental mode for the global taint configuration. */
  predicate observeDiffInformedIncrementalMode() { any() }

  /** Gets the source location to highlight for a selected sink. */
  Location getASelectedSinkLocation(DataFlow::Node sink) {
    exists(Expr e | result = e.getLocation() | isSink(sink, e, _))
  }
}

module Flow = TaintTracking::Global<Config>;

from Expr e, string effect, Flow::PathNode source, Flow::PathNode sink, string sourceType
where
  Flow::flowPath(source, sink) and
  isSource(source.getNode(), sourceType) and
  isSink(sink.getNode(), e, effect)
select e, source, sink,
  "$@ flows to an operand of an arithmetic expression, potentially causing an " + effect + ".",
  source, sourceType
