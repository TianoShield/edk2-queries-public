/**
 * Shared TaintInheritingContent models for NET_* types defined in
 * NetworkPkg/Include/Library/NetLib.h.
 */

import cpp
private import semmle.code.cpp.ir.dataflow.FlowSteps
private import semmle.code.cpp.dataflow.new.DataFlow

class NetBufStruct extends Struct {
  NetBufStruct() {
    exists(TypedefType t |
      t.hasName("NET_BUF") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

class NetBlockOpStruct extends Struct {
  NetBlockOpStruct() {
    exists(TypedefType t |
      t.hasName("NET_BLOCK_OP") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

class NetFragmentStruct extends Struct {
  NetFragmentStruct() {
    exists(TypedefType t |
      t.hasName("NET_FRAGMENT") and
      t.getBaseType().getUnderlyingType() = this
    )
  }
}

private class NetBufBlockOpField extends Field {
  NetBufBlockOpField() {
    this.hasName("BlockOp") and
    this.getDeclaringType().getUnderlyingType() instanceof NetBufStruct
  }
}

private class NetBufListField extends Field {
  NetBufListField() {
    this.hasName("List") and
    this.getDeclaringType().getUnderlyingType() instanceof NetBufStruct
  }
}

private class NetBlockOpPointerField extends Field {
  NetBlockOpPointerField() {
    this.getDeclaringType().getUnderlyingType() instanceof NetBlockOpStruct and
    this.getType().getUnspecifiedType() instanceof PointerType
  }
}

private class NetFragmentBulkField extends Field {
  NetFragmentBulkField() {
    this.hasName("Bulk") and
    this.getDeclaringType().getUnderlyingType() instanceof NetFragmentStruct
  }
}

/**
 * Models taint-preserving reads of the `NET_BUF.BlockOp` field from
 * `NetworkPkg/Include/Library/NetLib.h`.
 *
 * If the contents of a `NET_BUF` are tainted, then the corresponding
 * `NET_BLOCK_OP` array reached through `Nbuf->BlockOp` is also tainted.
 * This lets taint flow from packet bytes into the per-fragment metadata used by
 * helpers such as `NetbufGetByte`, `NetbufCopy`, and `NetbufBuildExt`.
 */
private class NetBufBlockOpTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  NetBufBlockOpTaintInheritingContent() {
    this.getField() instanceof NetBufBlockOpField and
    this.getIndirectionIndex() = 1
  }
}

/**
 * Models taint-preserving reads of the `NET_BUF.List` field from
 * `NetworkPkg/Include/Library/NetLib.h`.
 *
 * If a `NET_BUF` object is tainted, then its embedded `LIST_ENTRY` is tainted
 * as well. This lets list-building helpers preserve which packet objects were
 * inserted into a queue before a later `NetbufFromBufList` call reassembles
 * them into a new `NET_BUF`.
 */
private class NetBufListTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  NetBufListTaintInheritingContent() { this.getField() instanceof NetBufListField }
}

/**
 * Models taint-preserving reads of pointer-valued fields of the `NET_BLOCK_OP`
 * struct from `NetworkPkg/Include/Library/NetLib.h`.
 *
 * If the contents of a `NET_BLOCK_OP` are tainted, then the pointees reached
 * through `BlockHead`, `BlockTail`, `Head`, and `Tail` are also tainted.
 * Scalar fields such as `Size` are intentionally excluded.
 */
private class NetBlockOpPointerTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  NetBlockOpPointerTaintInheritingContent() {
    this.getField() instanceof NetBlockOpPointerField and
    this.getIndirectionIndex() = 2  // 2 means pointees are tainted
  }
}

/**
 * Models taint-preserving reads of the `NET_FRAGMENT.Bulk` field from
 * `NetworkPkg/Include/Library/NetLib.h`.
 *
 * If a `NET_FRAGMENT` object is tainted, then the bytes pointed to by
 * `NET_FRAGMENT.Bulk` are tainted as well. This is the pointer field consumed
 * by helpers such as `CopyMem` when a NET_BUF is flattened into fragments.
 */
private class NetFragmentBulkTaintInheritingContent extends TaintInheritingContent,
  DataFlow::FieldContent
{
  NetFragmentBulkTaintInheritingContent() {
    this.getField() instanceof NetFragmentBulkField and
    this.getIndirectionIndex() = 1
  }
}
