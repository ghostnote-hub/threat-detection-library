# threat-detection-library

A curated library of Sigma detection rules authored from the perspective of a Cybersecurity Architect. Each rule is tied to a real-world threat, vulnerability, or attacker technique — with supporting context, referenced blog posts, and MITRE ATT&CK mappings.

Rules are organized by MITRE ATT&CK tactic, with named sub-folders per threat or vulnerability.

---

## Structure

```
threat-detection-library/
├── privilege-escalation/
│   └── RedSun/
│       ├── README.md
│       ├── redsun-cfregistersyncroot-anomaly.yml
│       ├── redsun-ntfs-junction-system32.yml
│       ├── redsun-msmpeng-system32-write.yml
│       └── redsun-system-process-execution.yml
├── defense-evasion/
├── execution/
├── persistence/
├── lateral-movement/
├── credential-access/
└── README.md  <-- you are here
```

---

## Detection Index

| Threat / CVE | Tactic | Rule | Log Source | Level | Blog Post |
|---|---|---|---|---|---|
| RedSun / CVE-2026-33825 | Privilege Escalation | [CfRegisterSyncRoot Anomaly](./privilege-escalation/RedSun/redsun-cfregistersyncroot-anomaly.yml) | Windows ETW / EDR | High | [LinkedIn](https://www.linkedin.com/posts/activity-7451670974330015744-Vz0H?utm_source=share&utm_medium=member_desktop&rcm=ACoAAATDDj4Bs5d1YdKO8DXi2iazj1Jwo8C-Ny4) |
| RedSun / CVE-2026-33825 | Privilege Escalation | [NTFS Junction Targeting System32](./privilege-escalation/RedSun/redsun-ntfs-junction-system32.yml) | Sysmon EID 11 / MDE | High | [LinkedIn](https://www.linkedin.com/posts/activity-7451670974330015744-Vz0H?utm_source=share&utm_medium=member_desktop&rcm=ACoAAATDDj4Bs5d1YdKO8DXi2iazj1Jwo8C-Ny4) |
| RedSun / CVE-2026-33825 | Privilege Escalation | [MsMpEng.exe Anomalous System32 Write](./privilege-escalation/RedSun/redsun-msmpeng-system32-write.yml) | Sysmon EID 11 / MDE | Critical | [LinkedIn](https://www.linkedin.com/posts/activity-7451670974330015744-Vz0H?utm_source=share&utm_medium=member_desktop&rcm=ACoAAATDDj4Bs5d1YdKO8DXi2iazj1Jwo8C-Ny4) |
| RedSun / CVE-2026-33825 | Privilege Escalation | [SYSTEM Process via Cloud Files Service](./privilege-escalation/RedSun/redsun-system-process-execution.yml) | Sysmon EID 1 / MDE | Critical | [LinkedIn](https://www.linkedin.com/posts/activity-7451670974330015744-Vz0H?utm_source=share&utm_medium=member_desktop&rcm=ACoAAATDDj4Bs5d1YdKO8DXi2iazj1Jwo8C-Ny4) |


---

## Usage

Rules are written in [Sigma](https://github.com/SigmaHQ/sigma) format and can be converted to your target SIEM or EDR platform using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Example: convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rule.yml

# Example: convert to Splunk SPL
sigma convert -t splunk rule.yml

# Example: convert to Elastic Query DSL
sigma convert -t elasticsearch rule.yml
```

---

## Rule Status Definitions

| Status | Meaning |
|---|---|
| `stable` | Validated in production; low false positive rate confirmed |
| `test` | Validated in lab environment; tuning may be required in production |
| `experimental` | Based on threat intel and attack chain analysis; not yet lab-validated |

---

## Contributing & Feedback

If you identify false positives, evasion variants, or have tuning recommendations, open an issue or reach out directly. Detection engineering is iterative — community input is welcome.

---

## Author

Cybersecurity Architect | Detection Engineering | Threat Intelligence

- Personal Website: [https://www.stueck.us]
- LinkedIn: [https://www.linkedin.com/in/markstueck/]
- X: [https://x.com/MCS138]
- GitHub: [https://github.com/ghostnote-hub]
