/**
 * Models DebugLib assertion macros (`MdePkg/Include/Library/DebugLib.h`).
 */

import cpp

/**
 * Holds if `e` comes from the expansion of a DebugLib assertion macro. These
 * expand to nothing when `MDEPKG_NDEBUG` is defined (release builds), so a
 * check made only inside one is not error handling.
 */
predicate isInDebugAssertion(Element e) {
  exists(MacroInvocation mi |
    mi.getMacroName() = ["ASSERT", "ASSERT_EFI_ERROR", "ASSERT_RETURN_ERROR"] and
    mi.getAnExpandedElement() = e
  )
}
