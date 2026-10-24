/**
 * Shared flow-source model for the attacker-controlled device path that enters
 * EDK II through a registered security file-authentication handler. The
 * registration APIs and handler prototypes are declared in
 * `MdeModulePkg/Include/Library/SecurityManagementLib.h`.
 */

import cpp
private import semmle.code.cpp.security.FlowSources

/**
 * Holds if `f` is a registered security file-authentication handler, i.e. its
 * address is passed as the handler argument (argument 0) of
 * `RegisterSecurity2Handler` or `RegisterSecurityHandler`.
 *
 * Both handler prototypes — `SECURITY2_FILE_AUTHENTICATION_HANDLER` and
 * `SECURITY_FILE_AUTHENTICATION_STATE_HANDLER` — take the dispatched file's
 * device path as parameter index 1 (`AuthenticationStatus` is parameter 0).
 */
predicate isSecurityFileAuthHandler(Function f) {
  exists(FunctionCall call |
    call.getTarget().hasGlobalName(["RegisterSecurity2Handler", "RegisterSecurityHandler"]) and
    f.getAnAccess() = call.getArgument(0)
  )
}

/**
 * The attacker-controlled contents of the `File` device-path parameter
 * (parameter index 1) of a registered security file-authentication handler.
 *
 * The DXE core invokes these handlers to authenticate or measure an image
 * named by an untrusted device path (e.g. a boot option, or a path read from a
 * malicious GPT disk). `DxeTpm2MeasureBootHandler` and `DxeTpmMeasureBootHandler`
 * size this device path with `GetDevicePathSize` and add the result to a fixed
 * struct size with no overflow check (CVE-2022-36764 and the TPM 1.2 sibling),
 * so the pointed-to device-path bytes (`arg[*1]`) are treated as tainted.
 */
class Edk2SecurityFileAuthHandlerSource extends RemoteFlowSource {
  Edk2SecurityFileAuthHandlerSource() {
    exists(Function f |
      isSecurityFileAuthHandler(f) and
      this.asParameter(1) = f.getParameter(1)
    )
  }

  override string getSourceType() {
    result = "device path passed to a security file-authentication handler"
  }
}
