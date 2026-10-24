/**
 * Models all EDK2 BaseLib "string services" functions (BaseLib.h lines 580–2829)
 * as `ArrayFunction` subclasses.  The `ArrayFunction` predicates encode the
 * *specification-level* buffer contracts (null-termination requirements, which
 * parameter gives the buffer size, input vs. output direction) that CodeQL
 * cannot infer from source alone.
 *
 * TaintFunction, DataFlowFunction, SideEffectFunction, and
 * NonCppThrowingFunction are intentionally **not** used: EDK2 source is
 * available in the database, so CodeQL traces taint/dataflow through the
 * actual function bodies automatically.
 *
 * Function groups (by behavior):
 *   1.  StrLen / StrSize family                 — unbounded strlen / strsize
 *   2.  StrnLenS / StrnSizeS family             — bounded strlen / strsize
 *   3.  StrCmp / AsciiStriCmp family            — unbounded strcmp (incl. case-insensitive)
 *   4.  StrnCmp / AsciiStrnCmp                  — bounded strncmp
 *   5.  StrStr / AsciiStrStr                    — strstr (returns pointer into haystack)
 *   6.  StrCpyS / AsciiStrCpyS                  — safe strcpy (Dst, DestMax, Src)
 *   7.  StrnCpyS / AsciiStrnCpyS                — safe strncpy (Dst, DestMax, Src, Len)
 *   8.  StrCatS / AsciiStrCatS                  — safe strcat (Dst, DestMax, Src)
 *   9.  StrnCatS / AsciiStrnCatS                — safe strncat (Dst, DestMax, Src, Len)
 *  10.  Unicode↔ASCII full conversions          — UnicodeStrToAsciiStrS, AsciiStrToUnicodeStrS
 *  11.  Unicode↔ASCII bounded conversions       — UnicodeStrnToAsciiStrS, AsciiStrnToUnicodeStrS
 *  12.  String-to-integer legacy parsers        — StrDecimalToUintn, StrHexToUintn, etc.
 *  13.  String-to-integer safe parsers          — StrDecimalToUintnS, StrHexToUintnS, etc.
 *  14.  Structured-string parsers (IP, GUID)    — StrToIpv6Address, StrToGuid, etc.
 *  15.  Hex-string to byte-array                — StrHexToBytes, AsciiStrHexToBytes
 *  16.  Base64 encode / decode                  — Base64Encode, Base64Decode
 *
 * PrintLib functions are modeled separately in `lib/MdePkg/PrintLib.qll`.
 */

import cpp
import semmle.code.cpp.models.interfaces.ArrayFunction
import semmle.code.cpp.commons.NullTermination

// ---------------------------------------------------------------------------
// Group 1: StrLen / StrSize family — unbounded strlen / strsize
// ---------------------------------------------------------------------------

/**
 * EDK2 unbounded string-length / string-size functions:
 *   `StrLen(String)` / `AsciiStrLen(String)` — return character count
 *   `StrSize(String)` / `AsciiStrSize(String)` — return byte size incl. NUL
 *
 * Parameter 0 is scanned until `'\0'`; an unterminated buffer causes an
 * unbounded OOB read.
 */
class Edk2StrLenFunction extends ArrayFunction {
  Edk2StrLenFunction() {
    this.hasGlobalName(["StrLen", "AsciiStrLen", "StrSize", "AsciiStrSize"])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }
}

// ---------------------------------------------------------------------------
// Group 2: StrnLenS / StrnSizeS family — bounded strlen / strsize
// ---------------------------------------------------------------------------

/**
 * EDK2 bounded strlen / strsize functions:
 *   `StrnLenS(String, MaxSize)`      — Unicode, returns character count
 *   `StrnSizeS(String, MaxSize)`     — Unicode, returns byte size
 *   `AsciiStrnLenS(String, MaxSize)` — ASCII, returns character count
 *   `AsciiStrnSizeS(String, MaxSize)`— ASCII, returns byte size
 *
 * Param 0 is the string buffer scanned up to `MaxSize` (param 1) characters.
 */
class Edk2StrnLenSFunction extends ArrayFunction {
  Edk2StrnLenSFunction() {
    this.hasGlobalName(["StrnLenS", "StrnSizeS", "AsciiStrnLenS", "AsciiStrnSizeS"])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  // MaxSize (param 1) is a scan limit, not the buffer size.
}

// ---------------------------------------------------------------------------
// Group 3: StrCmp / AsciiStriCmp family — unbounded strcmp
// ---------------------------------------------------------------------------

/**
 * EDK2 unbounded string comparison functions:
 *   `StrCmp(FirstString, SecondString)` — Unicode, case-sensitive
 *   `AsciiStrCmp(FirstString, SecondString)` — ASCII, case-sensitive
 *   `AsciiStriCmp(FirstString, SecondString)` — ASCII, case-insensitive
 *
 * Both params must be null-terminated; either being unterminated causes
 * an unbounded OOB read.
 */
class Edk2StrCmpFunction extends ArrayFunction {
  Edk2StrCmpFunction() {
    this.hasGlobalName(["StrCmp", "AsciiStrCmp", "AsciiStriCmp"])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) {
    bufParam = 0 or bufParam = 1
  }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 or bufParam = 1 }
}

// ---------------------------------------------------------------------------
// Group 4: StrnCmp / AsciiStrnCmp — bounded strncmp
// ---------------------------------------------------------------------------

/**
 * EDK2 `StrnCmp(FirstString, SecondString, Length)` and
 * `AsciiStrnCmp(FirstString, SecondString, Length)`: compare at most `Length`
 * characters from two null-terminated strings.  Both buffers are bounded by
 * `Length` (param 2).
 */
class Edk2StrnCmpFunction extends ArrayFunction {
  Edk2StrnCmpFunction() { this.hasGlobalName(["StrnCmp", "AsciiStrnCmp"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) {
    bufParam = 0 or bufParam = 1
  }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 or bufParam = 1 }

  // Length (param 2) is a comparison limit, not the buffer size.
  // Both buffers are null-terminated.
}

// ---------------------------------------------------------------------------
// Group 5: StrStr / AsciiStrStr — strstr (returns pointer into haystack)
// ---------------------------------------------------------------------------

/**
 * EDK2 `StrStr(String, SearchString)` and
 * `AsciiStrStr(String, SearchString)`: return the first occurrence of
 * `SearchString` (param 1) in `String` (param 0), or `NULL` if not found.
 * Both params must be null-terminated.  The return value is a pointer into
 * the haystack buffer (param 0).
 */
class Edk2StrStrFunction extends ArrayFunction {
  Edk2StrStrFunction() { this.hasGlobalName(["StrStr", "AsciiStrStr"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) {
    bufParam = 0 or bufParam = 1
  }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 or bufParam = 1 }
}

// ---------------------------------------------------------------------------
// Groups 6–9: Safe string copy/cat functions
// ---------------------------------------------------------------------------

/**
 * EDK2 safe copy functions:
 *   `StrCpyS(Destination, DestMax, Source)`       — Unicode
 *   `AsciiStrCpyS(Destination, DestMax, Source)`  — ASCII
 *
 * Source (param 2) is null-terminated.  Destination (param 0) is bounded by
 * DestMax (param 1).  Returns `RETURN_STATUS`.
 */
class Edk2StrCpySFunction extends ArrayFunction {
  Edk2StrCpySFunction() { this.hasGlobalName(["StrCpyS", "AsciiStrCpyS"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 2 }

  override predicate hasArrayInput(int bufParam) { bufParam = 2 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 0 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 0 and countParam = 1
  }
}

/**
 * EDK2 safe bounded copy functions:
 *   `StrnCpyS(Destination, DestMax, Source, Length)`      — Unicode
 *   `AsciiStrnCpyS(Destination, DestMax, Source, Length)` — ASCII
 *
 * Source (param 2) is null-terminated; the copy stops at the earlier of
 * `'\0'` or `Length` (param 3) characters.  Destination (param 0) is bounded
 * by DestMax (param 1).  Returns `RETURN_STATUS`.
 */
class Edk2StrnCpySFunction extends ArrayFunction {
  Edk2StrnCpySFunction() { this.hasGlobalName(["StrnCpyS", "AsciiStrnCpyS"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 2 }

  override predicate hasArrayInput(int bufParam) { bufParam = 2 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 0 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 0 and countParam = 1
    // Length (param 3) is a copy limit, not Source's buffer size.
    // Source is null-terminated.
  }
}

/**
 * EDK2 safe concatenation functions:
 *   `StrCatS(Destination, DestMax, Source)`      — Unicode
 *   `AsciiStrCatS(Destination, DestMax, Source)` — ASCII
 *
 * Source (param 2) is null-terminated.  Destination (param 0) is both an
 * existing null-terminated input and the output buffer; DestMax (param 1)
 * is the total capacity.  The existing NUL in the destination is written
 * past during concatenation, so param 0 uses `hasArrayWithUnknownSize`
 * (consistent with strlcat modeling).  Returns `RETURN_STATUS`.
 */
class Edk2StrCatSFunction extends ArrayFunction {
  Edk2StrCatSFunction() { this.hasGlobalName(["StrCatS", "AsciiStrCatS"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithUnknownSize(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 or bufParam = 2 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 0 }

  // override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
  //   bufParam = 0 and countParam = 1
  // }
}

/**
 * EDK2 safe bounded concatenation functions:
 *   `StrnCatS(Destination, DestMax, Source, Length)`      — Unicode
 *   `AsciiStrnCatS(Destination, DestMax, Source, Length)` — ASCII
 *
 * At most `Length` (param 3) characters are appended from Source (param 2).
 * Source is null-terminated.  Destination (param 0) must be null-terminated
 * before the call; DestMax (param 1) is the total capacity.  The existing
 * NUL in the destination is written past during concatenation, so param 0
 * uses `hasArrayWithUnknownSize` (consistent with strlcat modeling).
 * Returns `RETURN_STATUS`.
 */
class Edk2StrnCatSFunction extends ArrayFunction {
  Edk2StrnCatSFunction() { this.hasGlobalName(["StrnCatS", "AsciiStrnCatS"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithUnknownSize(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 or bufParam = 2 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 0 }

  // override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
  //   bufParam = 0 and countParam = 1
  // }

  // Length (param 3) is an append limit, not Source's buffer size.
  // Source is null-terminated.
}

// ---------------------------------------------------------------------------
// Group 10: Unicode↔ASCII full conversions (null-terminated source)
// ---------------------------------------------------------------------------

/**
 * EDK2 full string conversion functions:
 *   `UnicodeStrToAsciiStrS(Source CHAR16*, Destination CHAR8*, DestMax)`
 *   `AsciiStrToUnicodeStrS(Source CHAR8*,  Destination CHAR16*, DestMax)`
 *
 * Source (param 0) must be null-terminated.  Destination (param 1) is the
 * output buffer; DestMax (param 2) is its capacity.  Returns `RETURN_STATUS`.
 */
class Edk2StrConversionFunction extends ArrayFunction {
  Edk2StrConversionFunction() {
    this.hasGlobalName(["UnicodeStrToAsciiStrS", "AsciiStrToUnicodeStrS"])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 1 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 1 and countParam = 2
  }
}

// ---------------------------------------------------------------------------
// Group 11: Unicode↔ASCII bounded conversions (Source bounded by Length)
// ---------------------------------------------------------------------------

/**
 * EDK2 bounded string conversion functions:
 *   `UnicodeStrnToAsciiStrS(Source, Length, Destination, DestMax, DestinationLength)`
 *   `AsciiStrnToUnicodeStrS(Source, Length, Destination, DestMax, DestinationLength)`
 *
 * Source (param 0) is a null-terminated string.  Length (param 1) is the
 * maximum number of characters to convert — a conversion limit, not the
 * buffer size.  Destination (param 2) is bounded by DestMax (param 3).
 * Returns `RETURN_STATUS`.
 */
class Edk2BoundedStrConvFunction extends ArrayFunction {
  Edk2BoundedStrConvFunction() {
    this.hasGlobalName(["UnicodeStrnToAsciiStrS", "AsciiStrnToUnicodeStrS"])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    // Length (param 1) is a conversion limit, not Source's buffer size.
    // Source is null-terminated.
    bufParam = 2 and countParam = 3
  }
}

// ---------------------------------------------------------------------------
// Groups 12 & 13: String-to-integer parsers (Unicode and ASCII)
// ---------------------------------------------------------------------------

/**
 * EDK2 string-to-integer conversion functions — legacy (no `S` suffix):
 *   `StrDecimalToUintn(String)`       `StrDecimalToUint64(String)`
 *   `StrHexToUintn(String)`           `StrHexToUint64(String)`
 *   `AsciiStrDecimalToUintn(String)`  `AsciiStrDecimalToUint64(String)`
 *   `AsciiStrHexToUintn(String)`      `AsciiStrHexToUint64(String)`
 *
 * All take a single null-terminated `String` (param 0) and return the parsed
 * integer directly.
 */
class Edk2StrToIntLegacyFunction extends ArrayFunction {
  Edk2StrToIntLegacyFunction() {
    this.hasGlobalName([
        "StrDecimalToUintn", "StrDecimalToUint64", "StrHexToUintn", "StrHexToUint64",
        "AsciiStrDecimalToUintn", "AsciiStrDecimalToUint64", "AsciiStrHexToUintn",
        "AsciiStrHexToUint64"
      ])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }
}

/**
 * EDK2 safe string-to-integer conversion functions (`S` suffix):
 *   `StrDecimalToUintnS(String, EndPointer, Data)`
 *   `StrDecimalToUint64S(String, EndPointer, Data)`
 *   `StrHexToUintnS(String, EndPointer, Data)`
 *   `StrHexToUint64S(String, EndPointer, Data)`
 *   `AsciiStrDecimalToUintnS(String, EndPointer, Data)`
 *   `AsciiStrDecimalToUint64S(String, EndPointer, Data)`
 *   `AsciiStrHexToUintnS(String, EndPointer, Data)`
 *   `AsciiStrHexToUint64S(String, EndPointer, Data)`
 *
 * `String` (param 0) is null-terminated.  Returns `RETURN_STATUS`.
 */
class Edk2StrToIntSafeFunction extends ArrayFunction {
  Edk2StrToIntSafeFunction() {
    this.hasGlobalName([
        "StrDecimalToUintnS", "StrDecimalToUint64S", "StrHexToUintnS", "StrHexToUint64S",
        "AsciiStrDecimalToUintnS", "AsciiStrDecimalToUint64S", "AsciiStrHexToUintnS",
        "AsciiStrHexToUint64S"
      ])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }
}

// ---------------------------------------------------------------------------
// Groups 14 & 15: Structured-string parsers (IP addresses, GUIDs)
// ---------------------------------------------------------------------------

/**
 * EDK2 functions that parse a null-terminated string into a structured type:
 *   `StrToIpv6Address(String, EndPointer, Address, PrefixLength)` — Unicode
 *   `StrToIpv4Address(String, EndPointer, Address, PrefixLength)` — Unicode
 *   `AsciiStrToIpv6Address(String, EndPointer, Address, PrefixLength)` — ASCII
 *   `AsciiStrToIpv4Address(String, EndPointer, Address, PrefixLength)` — ASCII
 *
 * `String` (param 0) is null-terminated.  Returns `RETURN_STATUS`.
 */
class Edk2StrToIpAddressFunction extends ArrayFunction {
  Edk2StrToIpAddressFunction() {
    this.hasGlobalName([
        "StrToIpv6Address", "StrToIpv4Address", "AsciiStrToIpv6Address", "AsciiStrToIpv4Address"
      ])
  }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }
}

/**
 * EDK2 functions that parse a null-terminated GUID string:
 *   `StrToGuid(String, Guid)`      — Unicode
 *   `AsciiStrToGuid(String, Guid)` — ASCII
 */
class Edk2StrToGuidFunction extends ArrayFunction {
  Edk2StrToGuidFunction() { this.hasGlobalName(["StrToGuid", "AsciiStrToGuid"]) }

  override predicate hasArrayWithNullTerminator(int bufParam) { bufParam = 0 }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }
}

// ---------------------------------------------------------------------------
// Group 15: Hex-string to byte-array
// ---------------------------------------------------------------------------

/**
 * EDK2 hex-decode functions:
 *   `StrHexToBytes(String, Length, Buffer, MaxBufferSize)`      — Unicode
 *   `AsciiStrHexToBytes(String, Length, Buffer, MaxBufferSize)` — ASCII
 *
 * `String` (param 0) is documented as a null-terminated string but the
 * function reads exactly `Length` (param 1) hex characters (rejecting any
 * null within that span), so the read is bounded by `Length`, not null
 * termination.  `Buffer` (param 2) receives the decoded bytes;
 * `MaxBufferSize` (param 3) is the capacity of `Buffer`.
 * Returns `RETURN_STATUS`.
 */
class Edk2StrHexToBytesFunction extends ArrayFunction {
  Edk2StrHexToBytesFunction() { this.hasGlobalName(["StrHexToBytes", "AsciiStrHexToBytes"]) }

  // Read bounded by Length (param 1), not null termination.
  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 0 and countParam = 1
    or
    bufParam = 2 and countParam = 3
  }
}

// ---------------------------------------------------------------------------
// Group 16: Base64 encode / decode
// ---------------------------------------------------------------------------

/**
 * EDK2 `Base64Encode(Source, SourceLength, Destination, DestinationSize)`:
 * converts binary bytes at `Source` (param 0, bounded by `SourceLength`
 * param 1) to a Base64 ASCII string at `Destination` (param 2).
 * `DestinationSize` (param 3) is `UINTN*` (pointer to size), so it cannot
 * be modeled via `hasArrayWithVariableSize`.  Returns `RETURN_STATUS`.
 */
class Edk2Base64EncodeFunction extends ArrayFunction {
  Edk2Base64EncodeFunction() { this.hasGlobalName("Base64Encode") }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 0 and countParam = 1
  }
}

/**
 * EDK2 `Base64Decode(Source, SourceSize, Destination, DestinationSize)`:
 * decodes Base64 ASCII bytes at `Source` (param 0, bounded by `SourceSize`
 * param 1) into binary at `Destination` (param 2).
 * `DestinationSize` (param 3) is `UINTN*` (pointer to size), so it cannot
 * be modeled via `hasArrayWithVariableSize`.  Returns `RETURN_STATUS`.
 */
class Edk2Base64DecodeFunction extends ArrayFunction {
  Edk2Base64DecodeFunction() { this.hasGlobalName("Base64Decode") }

  override predicate hasArrayInput(int bufParam) { bufParam = 0 }

  override predicate hasArrayOutput(int bufParam) { bufParam = 2 }

  override predicate hasArrayWithVariableSize(int bufParam, int countParam) {
    bufParam = 0 and countParam = 1
  }
}

/**
 * A BaseLib character-class predicate that returns true only for a decimal or
 * hexadecimal digit character: `InternalAsciiIsDecimalDigitCharacter`,
 * `InternalAsciiIsHexaDecimalDigitCharacter` (CHAR8, `SafeString.c`), and the
 * CHAR16 forms `InternalIsDecimalDigitCharacter` /
 * `InternalIsHexaDecimalDigitCharacter` (`String.c`).
 *
 * Unlike the buffer models above this is a plain marker class, not an
 * `ArrayFunction`: it lets a query treat a call to one of these as a guard that
 * constrains its argument to a digit character — and therefore to a code point
 * `>= '0'` (every decimal/hex digit glyph is `'0'` or greater) — so a `c - '0'`
 * style decode in the guarded block cannot underflow.
 */
class Edk2DigitCharacterClassFunction extends Function {
  Edk2DigitCharacterClassFunction() {
    this.hasGlobalName([
        "InternalAsciiIsDecimalDigitCharacter",
        "InternalAsciiIsHexaDecimalDigitCharacter",
        "InternalIsDecimalDigitCharacter",
        "InternalIsHexaDecimalDigitCharacter"
      ])
  }
}
