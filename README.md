# edk2-queries

CodeQL queries for detecting security vulnerabilities in EDK2. The queries
target reusable root-cause patterns rather than specific functions or files.

## CVE coverage

The following table maps EDK2 CVEs from the
[published TianoCore security advisories](https://github.com/tianocore/edk2/security/advisories?state=published)
to the queries that detect them. Vulnerabilities are listed as `Package:
advisory title`; shared advisories also include CVE-specific details.

| CVE | Query | Vulnerability |
|---|---|---|
| CVE-2025-3770 | No query | UefiCpuPkg: [SMM IDT privilege escalation vulnerability](https://github.com/tianocore/edk2/security/advisories/GHSA-vx5v-4gg6-6qxr) |
| CVE-2025-2296 | No query | OvmfPkg: [Un-verified kernel bypass Secure Boot mechanism in direct boot mode](https://github.com/tianocore/edk2/security/advisories/GHSA-6pp6-cm5h-86g5) |
| CVE-2025-2295 | `ArithmeticTainted.ql` | NetworkPkg: [Remote Memory Exposure in iSCSI DXE](https://github.com/tianocore/edk2/security/advisories/GHSA-8522-69fh-w74x) |
| CVE-2024-38805 | `ArithmeticTainted.ql` | NetworkPkg: [iSCSI Remote Memory Corruption and Denial of Service](https://github.com/tianocore/edk2/security/advisories/GHSA-p7wp-52j7-6r5x) |
| CVE-2024-38798 | No query | MdeModulePkg: [MdeModulePkg/Bus/Usb/UsbKbDxe: Uncleared password keystrokes in circular queue can lead to information disclosure or escalation of privilege](https://github.com/tianocore/edk2/security/advisories/GHSA-q2c6-37h5-7cwf) |
| CVE-2024-38797 | `TaintedUnguardedOffsetRead.ql` | SecurityPkg: [Out of bound read in HashPeImageByType](https://github.com/tianocore/edk2/security/advisories/GHSA-4wjw-6xmf-44xf) |
| CVE-2024-38796 | `ArithmeticTainted.ql` | MdePkg: [Integer overflows in PeCoffLoaderRelocateImage](https://github.com/tianocore/edk2/security/advisories/GHSA-xpcr-7hjq-m6qm) |
| CVE-2024-1298 | `ArithmeticTainted.ql` | MdeModulePkg: [Temporary DoS vulnerability in FirmwarePerformancePei](https://github.com/tianocore/edk2/security/advisories/GHSA-chfw-xj8f-6m53) |
| CVE-2023-45237 | No query | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - weak PRNG in network stack randomness |
| CVE-2023-45236 | No query | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - predictable TCP initial sequence numbers |
| CVE-2023-45235 | `TaintedBaseMemoryLibLength.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - DHCPv6 proxy Advertise Server ID option buffer overflow |
| CVE-2023-45234 | `TaintedAllocationFixedAccessLength.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - DHCPv6 Advertise DNS Servers option buffer overflow |
| CVE-2023-45233 | `ArithmeticTainted.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - infinite loop parsing IPv6 Destination Options PadN option |
| CVE-2023-45232 | `ArithmeticTainted.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - infinite loop parsing unknown IPv6 Destination Options |
| CVE-2023-45231 | `TaintedUnguardedOffsetRead.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - OOB read handling IPv6 ND Redirect messages with truncated options |
| CVE-2023-45230 | `TaintedBaseMemoryLibLength.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - DHCPv6 client buffer overflow via long Server ID option |
| CVE-2023-45229 | `ArithmeticTainted.ql` | NetworkPkg: [Vulnerabilities in EDK2 NetworkPkg IP stack implementation](https://github.com/tianocore/edk2/security/advisories/GHSA-hc6x-cw6p-gj7h) - OOB read processing IA_NA and IA_TA options in DHCPv6 Advertise messages |
| CVE-2022-36765 | `ArithmeticTainted.ql` | UefiPayloadPkg: [Integer Overflow in CreateHob() could lead to HOB OOB R/W](https://github.com/tianocore/edk2/security/advisories/GHSA-ch4w-v7m3-g8wx) |
| CVE-2022-36764 | `ArithmeticTainted.ql` | SecurityPkg: [Heap Buffer Overflow in Tcg2MeasurePeImage()](https://github.com/tianocore/edk2/security/advisories/GHSA-4hcq-p8q8-hj8j) |
| CVE-2022-36763 | `ArithmeticTainted.ql` | SecurityPkg: [Heap Buffer Overflow in Tcg2MeasureGptTable()](https://github.com/tianocore/edk2/security/advisories/GHSA-xvv8-66cq-prwr) |

## Query scope

- `ArithmeticTainted.ql` detects tainted arithmetic flaws, including overflow,
  underflow, and non-progressing loop updates. Its models cover the CVEs mapped
  above, including both related IPv6 Destination Options defects tracked as
  CVE-2023-45232 and CVE-2023-45233.
- `TaintedUnguardedOffsetRead.ql` detects attacker-controlled data used in
  constant-offset reads without a dominating length guard (CWE-125). It covers
  CVE-2024-38797 and CVE-2023-45231.
- `TaintedBaseMemoryLibLength.ql` detects attacker-controlled lengths passed to
  `BaseMemoryLib` memory operations without a dominating upper-bound guard
  (CWE-787/805). It covers CVE-2023-45235 and CVE-2023-45230 through reusable
  DHCPv6 flow-source models.
- `TaintedAllocationFixedAccessLength.ql` detects attacker-controlled pool
  allocation sizes followed by fixed-length `BaseMemoryLib` accesses
  (CWE-131/787/125). It covers CVE-2023-45234 through a reusable DHCPv6 option
  source and a lower-bound guard barrier.
- `TaintedNullTerminatedStringFunction.ql` detects attacker-controlled buffers
  passed to string APIs that require null termination (CWE-170/125).
- `UnguardedDecFollowingLoop.ql` and
  `UnguardedAssignSubExprInLoop.ql` provide additional syntactic coverage for
  CVE-2024-38805.
- `unsafe-u32-field-addition-without-overflow-check.ql` detects range and end
  calculations that add unsigned 32-bit structure fields without a nearby
  overflow guard (CWE-190).

The repository includes synthetic BAD/GOOD test cases under `test/`.

## CVEs without reusable queries

Some root causes do not map cleanly to reusable C/C++ data-flow, arithmetic, or
memory-safety properties. A query tailored to a particular function, constant,
or implementation detail would provide little value beyond matching the known
defect.

| CVE | Reason |
|---|---|
| CVE-2025-3770 | The flaw depends on assembly-level SMM initialization order, processor state, and exception-delivery semantics outside the CodeQL C/C++ database. |
| CVE-2025-2296 | The memory-safe direct-boot fallback violates Secure Boot policy; detection requires application-specific knowledge of authentication failures and permitted boot paths. |
| CVE-2024-38798 | Detecting uncleared password keystrokes requires modeling sensitive-data lifetimes and secure erasure rather than unsafe memory access. |
| CVE-2023-45237 | Assessing PRNG strength requires reasoning about algorithm quality, seed entropy, attacker observations, and each value's security requirements. Flagging `NET_RANDOM` alone would be an API blacklist. |
| CVE-2023-45236 | Predictable TCP sequence numbers are a protocol-level weakness. Matching the current constants or update expression would not generalize to other weak generators. |

Reusable CodeQL analysis is strongest when a defect can be expressed through
syntax, control flow, data flow, taint, arithmetic constraints, or memory-access
relationships. Assembly semantics, cryptographic strength, protocol-specific
unpredictability, secret lifetimes, and application security policy generally
require different analysis techniques.
