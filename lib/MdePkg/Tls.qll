/**
 * Shared TaintInheritingContent models for types defined in
 * MdePkg/Include/Protocol/Tls.h.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

class TlsVersionStruct extends Struct {
  TlsVersionStruct() {
    exists(TypedefType t |
      t.hasName("EFI_TLS_VERSION") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class TlsVersionField extends Field {
  TlsVersionField() {
    this.getDeclaringType().getUnderlyingType() instanceof TlsVersionStruct and
    this.getType().getUnderlyingType() instanceof ArithmeticType
  }
}

/**
 * Models all scalar fields of:
 *
 * `typedef struct {`
 * `  UINT8 Major;`
 * `  UINT8 Minor;`
 * `} EFI_TLS_VERSION;`
 *
 * Once taint has flowed into an `EFI_TLS_VERSION` object, it further inherits
 * to `EFI_TLS_VERSION.Major` and `EFI_TLS_VERSION.Minor`.
 */
private class TlsVersionTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  TlsVersionTaintInheritingContent() { this.getField() instanceof TlsVersionField }
}
