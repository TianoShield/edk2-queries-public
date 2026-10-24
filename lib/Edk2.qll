/**
 * Query-facing aggregate import for reusable EDK2 models.
 *
 * Root queries should import this file instead of importing individual model
 * files directly.  Package/API-specific model files are imported here so their
 * organization can change without forcing query import churn.
 */

import lib.MdePkg.BaseLib
import lib.MdePkg.BaseLibString
import lib.MdePkg.BaseLibSwapBytes
import lib.MdePkg.BaseMemoryLib
import lib.MdePkg.BlockIo
import lib.MdePkg.Dhcp4
import lib.MdePkg.Dhcp6
import lib.MdePkg.DevicePathUtilities
import lib.MdePkg.DiskIo
import lib.MdePkg.Hob
import lib.MdePkg.LinkedList
import lib.MdePkg.MemoryAllocationLib
import lib.MdePkg.PeCoffLib
import lib.MdePkg.PeImage
import lib.MdePkg.PrintLib
import lib.MdePkg.Tls
import lib.MdePkg.Tls1
import lib.MdePkg.UefiGpt
import lib.MdeModulePkg.CoreDxeMem
import lib.MdeModulePkg.FirmwarePerformance
import lib.MdeModulePkg.SecurityManagementLib
import lib.SecurityPkg.DxeImageVerificationLib
import lib.SecurityPkg.DxeTpmMeasureBootLibSanitization
import lib.CryptoPkg.OpensslLib
import lib.CryptoPkg.MbedTlsLib
import lib.CryptoPkg.ThirdPartyCrypto
import lib.NetworkPkg.Dhcp6Dxe
import lib.NetworkPkg.HttpsSupport
import lib.NetworkPkg.Ip6If
import lib.NetworkPkg.IScsiProto
import lib.NetworkPkg.NetBuffer
import lib.NetworkPkg.NetLib
import lib.NetworkPkg.PxeBcDhcp6
import lib.NetworkPkg.TcpIo
import lib.NetworkPkg.UdpIo
