/**
 * Models EDK2 PrintLib functions (MdePkg/Include/Library/PrintLib.h) as
 * `FormattingFunction` subclasses for taint tracking and null-termination
 * analysis.
 *
 * Every function models its format-string parameter as a null-terminated
 * input.  This makes a tainted, potentially-unterminated buffer reaching
 * any of these calls a CWE-170 sink.  For the variadic functions
 * (UnicodeSPrint, AsciiSPrint, and the cross-charset *AsciiFormat /*
 * UnicodeFormat variants), CodeQL can additionally resolve `%s` conversion
 * arguments from the format string, enabling CWE-170 detection when a
 * tainted value is passed as a `%s` argument.
 *
 * VA_LIST / BASE_LIST variants (UnicodeVSPrint, UnicodeBSPrint, etc.) cannot
 * expose their format arguments to CodeQL since they are not variadic C
 * functions.  They still correctly model the format string itself as a
 * null-terminated input.
 *
 * Intentionally not modeled:
 *   UnicodeValueToStringS, AsciiValueToStringS — numeric-to-string
 *   conversions; no format string, no null-termination sink.
 *
 * Covered by class:
 *   Edk2PrintFunction        — Print, AsciiPrint
 *   Edk2SPrintFunction       — UnicodeSPrint, AsciiSPrint,
 *                              UnicodeSPrintAsciiFormat, AsciiSPrintUnicodeFormat
 *   Edk2VSBSPrintFunction    — UnicodeVSPrint, UnicodeBSPrint,
 *                              UnicodeVSPrintAsciiFormat, UnicodeBSPrintAsciiFormat,
 *                              AsciiVSPrint, AsciiBSPrint,
 *                              AsciiVSPrintUnicodeFormat, AsciiBSPrintUnicodeFormat
 *   Edk2SPrintLengthFunction — SPrintLength, SPrintLengthAsciiFormat
 */

import cpp
import semmle.code.cpp.models.interfaces.FormattingFunction

// ---------------------------------------------------------------------------
// Print family — write formatted output directly to the console
// ---------------------------------------------------------------------------

/**
 * EDK2 `Print` and `AsciiPrint`:
 *   Print     (CONST CHAR16 *Format, ...)
 *   AsciiPrint(CONST CHAR8  *Format, ...)
 *
 * Format string at parameter 0; variadic arguments start at parameter 1.
 * Output goes to the EFI console (no output-buffer parameter).
 */
class Edk2PrintFunction extends FormattingFunction {
  Edk2PrintFunction() { this.hasGlobalName(["Print", "AsciiPrint"]) }

  override int getFormatParameterIndex() { result = 0 }

  override predicate isOutputGlobal() { any() }
}

// ---------------------------------------------------------------------------
// SPrint family — variadic, write to a caller-supplied buffer
// ---------------------------------------------------------------------------

/**
 * EDK2 variadic SPrint functions:
 *   UnicodeSPrint         (Buffer, BufferSize, FormatString, ...)  Unicode fmt → Unicode out
 *   AsciiSPrint           (Buffer, BufferSize, FormatString, ...)  ASCII fmt  → ASCII out
 *   UnicodeSPrintAsciiFormat(Buffer, BufferSize, FormatString, ...) ASCII fmt → Unicode out
 *   AsciiSPrintUnicodeFormat(Buffer, BufferSize, FormatString, ...) Unicode fmt → ASCII out
 *
 * All share the same parameter layout:
 *   param 0 — output buffer
 *   param 1 — buffer size (in bytes)
 *   param 2 — null-terminated format string
 *   param 3+ — variadic format arguments
 */
class Edk2SPrintFunction extends FormattingFunction {
  Edk2SPrintFunction() {
    this.hasGlobalName([
        "UnicodeSPrint", "AsciiSPrint",
        "UnicodeSPrintAsciiFormat", "AsciiSPrintUnicodeFormat"
      ])
  }

  override int getFormatParameterIndex() { result = 2 }

  override int getOutputParameterIndex(boolean isStream) { result = 0 and isStream = false }

  override int getSizeParameterIndex() { result = 1 }
}

// ---------------------------------------------------------------------------
// VSPrint / BSPrint family — non-variadic (VA_LIST / BASE_LIST) variants
// ---------------------------------------------------------------------------

/**
 * EDK2 non-variadic SPrint functions that accept a pre-built `VA_LIST` or
 * `BASE_LIST` instead of `...`:
 *   UnicodeVSPrint            (Buffer, BufferSize, FormatString, VA_LIST)
 *   UnicodeBSPrint            (Buffer, BufferSize, FormatString, BASE_LIST)
 *   UnicodeVSPrintAsciiFormat (Buffer, BufferSize, FormatString, VA_LIST)
 *   UnicodeBSPrintAsciiFormat (Buffer, BufferSize, FormatString, BASE_LIST)
 *   AsciiVSPrint              (Buffer, BufferSize, FormatString, VA_LIST)
 *   AsciiBSPrint              (Buffer, BufferSize, FormatString, BASE_LIST)
 *   AsciiVSPrintUnicodeFormat (Buffer, BufferSize, FormatString, VA_LIST)
 *   AsciiBSPrintUnicodeFormat (Buffer, BufferSize, FormatString, BASE_LIST)
 *
 * Because these are not variadic C functions, CodeQL cannot index the
 * individual format arguments passed through the `VA_LIST` / `BASE_LIST`.
 * We still extend `FormattingFunction` so that the format string (param 2)
 * is modeled as a null-terminated input, making it a CWE-170 sink when
 * tainted.  `getFirstFormatArgumentIndex()` resolves to the total parameter
 * count (4), so no spurious format-argument alerts are generated.
 */
class Edk2VSBSPrintFunction extends FormattingFunction {
  Edk2VSBSPrintFunction() {
    this.hasGlobalName([
        "UnicodeVSPrint", "UnicodeBSPrint",
        "UnicodeVSPrintAsciiFormat", "UnicodeBSPrintAsciiFormat",
        "AsciiVSPrint", "AsciiBSPrint",
        "AsciiVSPrintUnicodeFormat", "AsciiBSPrintUnicodeFormat"
      ])
  }

  override int getFormatParameterIndex() { result = 2 }

  override int getOutputParameterIndex(boolean isStream) { result = 0 and isStream = false }

  override int getSizeParameterIndex() { result = 1 }
}

// ---------------------------------------------------------------------------
// SPrintLength family — measure the output length without writing
// ---------------------------------------------------------------------------

/**
 * EDK2 format-length functions:
 *   SPrintLength           (CONST CHAR16 *FormatString, VA_LIST Marker)
 *   SPrintLengthAsciiFormat(CONST CHAR8  *FormatString, VA_LIST Marker)
 *
 * These compute the number of characters that `FormatString` (param 0) would
 * produce and return it; they write to no output buffer.  The format string
 * is still a null-terminated input (CWE-170 sink).
 *
 * Both take a `VA_LIST` Marker as their second argument.  Like the VSPrint/BSPrint
 * functions above, they are not variadic C functions, so
 * `getFirstFormatArgumentIndex()` == 2 and no format arguments are tracked.
 */
class Edk2SPrintLengthFunction extends FormattingFunction {
  Edk2SPrintLengthFunction() {
    this.hasGlobalName(["SPrintLength", "SPrintLengthAsciiFormat"])
  }

  override int getFormatParameterIndex() { result = 0 }
  // No output buffer; no isOutputGlobal() — this function purely returns a
  // length value and has no string-output side-effect.
}
