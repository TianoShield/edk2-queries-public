/**
 * Shared TaintInheritingContent models for types defined in
 * MdePkg/Include/IndustryStandard/Tls1.h.
 */

import cpp
import lib.MdePkg.Tls
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

class TlsRecordHeaderStruct extends Struct {
  TlsRecordHeaderStruct() {
    exists(TypedefType t |
      t.hasName("TLS_RECORD_HEADER") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class TlsRecordHeaderField extends Field {
  TlsRecordHeaderField() {
    this.getDeclaringType().getUnderlyingType() instanceof TlsRecordHeaderStruct and
    (
      this.getType().getUnderlyingType() instanceof ArithmeticType
      or
      this.getType().getUnderlyingType() instanceof TlsVersionStruct
    )
  }
}

/**
 * Models all scalar fields of, plus the nested `Version` field in:
 *
 * `typedef struct {`
 * `  UINT8 ContentType;`
 * `  EFI_TLS_VERSION Version;`
 * `  UINT16 Length;`
 * `} TLS_RECORD_HEADER;`
 *
 * Taint on a `TLS_RECORD_HEADER` object inherits to
 * `TLS_RECORD_HEADER.ContentType`, `TLS_RECORD_HEADER.Length`, and the nested
 * `TLS_RECORD_HEADER.Version` subobject so that taint can continue into
 * `EFI_TLS_VERSION.Major` and `EFI_TLS_VERSION.Minor`.
 */
private class TlsRecordHeaderTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  TlsRecordHeaderTaintInheritingContent() { this.getField() instanceof TlsRecordHeaderField }
}
