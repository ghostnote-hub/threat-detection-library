# RedSun — Windows Defender Zero-Day (CVE-2026-33825)

## Overview

RedSun is an unpatched Local Privilege Escalation (LPE) zero-day targeting Microsoft Defender's cloud file handling logic. A low-privileged local user can escalate to SYSTEM on fully patched Windows 10, Windows 11, and Windows Server 2019+ systems where Windows Defender is enabled and `cldapi.dll` is present.

Publicly disclosed in April 2026 by researcher "Chaotic Eclipse" (GitHub: Nightmare-Eclipse). No patch is available as of the date of this writing.

> Reference: [BleepingComputer — New Microsoft Defender "RedSun" zero-day PoC grants SYSTEM privileges](https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/)

> Associated Blog Post: [LinkedIn — When Your AV Becomes the Attack Vector](#) *(update with final URL)*

---

## CVE & Classification

| Field | Value |
|---|---|
| CVE | CVE-2026-33825 |
| CVSS | 7.8 (High) |
| CWE | CWE: Insufficient Granularity of Access Control |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | T1068 — Exploitation for Privilege Escalation |
| Patch Status | **Unpatched as of April 2026** |

---

## Attack Chain Summary

The exploit operates in four discrete stages:

1. **Cloud Files Sync Root Registration** — The attacker registers a fake Cloud Files sync root using `CfRegisterSyncRoot` via `cldapi.dll`, staging a cloud-tagged malicious file (typically an EICAR variant) for Defender to detect.

2. **Oplock Synchronization** — An opportunistic lock (oplock) is placed on the staged file to pause Defender's remediation write mid-operation, creating a controlled race window.

3. **NTFS Junction Redirect** — While Defender is suspended, the attacker swaps the target directory for an NTFS junction (mount point reparse) pointing to `C:\Windows\System32`. The oplock is released.

4. **Privileged Write and Execution** — Defender resumes and follows the redirected path, writing attacker-controlled content (e.g., a malicious binary) directly into `System32` under SYSTEM privileges. The overwritten service binary (commonly `TieringEngineService.exe`) is then executed, yielding full SYSTEM-level code execution.

The root cause is the absence of reparse point validation in `MpSvc.dll`. The detection path and write-back path are not reconciled — a single call to `DeviceIoControl(FSCTL_GET_REPARSE_POINT)` before the write would have prevented this entirely.

---

## Detection Rules

| Rule File | Stage Covered | Log Source | Level |
|---|---|---|---|
| [redsun-cfregistersyncroot-anomaly.yml](./redsun-cfregistersyncroot-anomaly.yml) | Stage 1 — Sync root registration | Windows ETW / EDR | High |
| [redsun-ntfs-junction-system32.yml](./redsun-ntfs-junction-system32.yml) | Stage 3 — NTFS junction creation | Sysmon EID 11 / MDE | High |
| [redsun-msmpeng-system32-write.yml](./redsun-msmpeng-system32-write.yml) | Stage 4 — Defender write to System32 | Sysmon EID 11 / MDE | Critical |
| [redsun-system-process-execution.yml](./redsun-system-process-execution.yml) | Stage 4 — SYSTEM process execution | Sysmon EID 1 / MDE | Critical |

Rules covering Stages 1 and 3 are best used for hunting and correlation. Rules covering Stage 4 are the highest-fidelity alerting candidates with the lowest expected false positive rate.

---

## Recommended Log Sources

- **Sysmon**: Event IDs 1 (Process Create), 11 (File Create), 23 (File Delete)
- **Microsoft Defender for Endpoint**: FileCreated, ProcessCreated, DeviceFileEvents
- **ETW Provider**: `Microsoft-Windows-CloudFiles` for `CfRegisterSyncRoot` telemetry
- **Windows Security Event Log**: EID 4688 (Process Creation) with command line auditing enabled

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| File Path | `C:\Windows\System32\TieringEngineService.exe` | Monitor for unexpected hash changes |
| Process | `MsMpEng.exe` writing to `System32` | Outside of Defender platform updates |
| File System | NTFS junction in `%TEMP%` targeting `System32` | No legitimate use case for standard users |
| API Call | `CfRegisterSyncRoot` from non-sync-client process | Known PoC uses provider name `SERIOUSLYMSFT` |

---

## Compensating Controls (Until Patch Available)

- Supplement Windows Defender with a third-party EDR capable of detecting Defender bypasses and anomalous filesystem operations
- Enforce strict least-privilege — RedSun is an LPE, meaning initial access is a prerequisite
- Implement File Integrity Monitoring (FIM) on `C:\Windows\System32` for unexpected binary changes
- Enable Microsoft Defender Tamper Protection
- Monitor for and alert on unexpected service restarts, particularly `TieringEngineService`
- Apply the April 2026 Patch Tuesday cumulative updates to close the BlueHammer vector (CVE-2026-33825), even though it does not address RedSun

---

## References

- [BleepingComputer — RedSun PoC](https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/)
- [CloudSEK — Technical Deep Dive](https://www.cloudsek.com/blog/redsun-windows-0day-when-defender-becomes-the-attacker)
- [CSO Online — RedSun Coverage](https://www.csoonline.com/article/4160275/caught-quarantined-re-installed-redsun-turns-microsoft-defender-on-itself.html)
- [Blackswan Cybersecurity — Threat Advisory](https://blackswan-cybersecurity.com/threat-advisory-redsun-zero-day-windows-defender-april-17-2026/)
