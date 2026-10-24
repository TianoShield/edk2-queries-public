/**
 * Shared TaintFunction models for the device-path helpers defined in
 * `MdePkg/Library/UefiDevicePathLib/DevicePathUtilities.c`.
 */

import cpp
import semmle.code.cpp.models.interfaces.Taint

/**
 * Models:
 *
 * `UINTN GetDevicePathSize(CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath)`
 *
 * The returned size is `((UINTN)End - (UINTN)Start) + DevicePathNodeLength(End)`
 * — it is governed by the attacker-controlled per-node `Length` fields walked
 * out of `DevicePath`, but reaches the integer result only through
 * pointer-difference arithmetic, which ordinary IR taint does not carry. This
 * summary restores the dropped step so a tainted device path produces a tainted
 * size: `arg[*0] -> return`.
 */
class GetDevicePathSizeTaintFunction extends Function, TaintFunction {
  GetDevicePathSizeTaintFunction() {
    this.hasGlobalName(["GetDevicePathSize", "UefiDevicePathLibGetDevicePathSize"])
  }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValue()
  }
}

/**
 * Models:
 *
 * `EFI_DEVICE_PATH_PROTOCOL *DuplicateDevicePath(CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath)`
 *
 * `DuplicateDevicePath` returns `AllocateCopyPool(GetDevicePathSize(DevicePath),
 * DevicePath)` — a freshly allocated byte-for-byte copy of the input device
 * path. The copy's bytes are therefore as attacker-controlled as the input's,
 * so taint flows content-to-content: `arg[*0] -> return[*0]`. The TPM measure-
 * boot handlers duplicate the untrusted `File` path here before sizing it, and
 * the allocate-then-copy round trip otherwise loses the content taint.
 */
class DuplicateDevicePathTaintFunction extends Function, TaintFunction {
  DuplicateDevicePathTaintFunction() {
    this.hasGlobalName(["DuplicateDevicePath", "UefiDevicePathLibDuplicateDevicePath"])
  }

  override predicate hasTaintFlow(FunctionInput input, FunctionOutput output) {
    input.isParameterDeref(0) and
    output.isReturnValueDeref()
  }
}
