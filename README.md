
<img width="800" height="300" src="https://i.ibb.co/m5v04zyH/uiinuiibanner.png">

## (UII-NUII) - Linux Based Reconnaissance Framework
###### UII-NUII ___'Unified Intrusion Inventory & Network Utility Inspection Instrument'___ Is a Linux based C/C++  Post Exploitation, Vulnerability Management & Reconniassance Framework designed for the purposes of system security mitigation and blue team research, written purely in C and C++ with no additional dependancies and 1 file design for ease of usage and compatibility- any issues or questions: prv@anche.no
------

## Compatibility and Usage 

To Run UII-NUII You can simply download the pre-compiled executable or compile the source code directly onto your Linux OS, all versions of Linux are supported with the framework but functionality may depend on **Internet Connection and Type** along with **Installed packages** and **Hardware Type** Running on the machine.

Although this may not prevent the program from running it may have an effect on the effectiveness and how you use the framework to your benefit, any antivirus or rootkit detection frameworks along with potential local firewalls may also effect the stability but will not prevent overall run- **Root Privilages** are not required or needed to run but may effect some of the features; but those are indicated as such for those that might be effected by lack of privilages.

## Features of (UII-NUII)
---

<img width="800" height="400" src="https://i.ibb.co/B2TxVnxY/uiinuiifeatures.png">

UII-NUII is an on‑host reconnaissance toolkit that produces concise, auditable snapshots of a machine’s hardware, OS/software footprint, network posture, and privilege‑hygiene — designed for authorized inventory, triage, and defensive hardening. It exposes modular, on‑demand checks (many gated behind elevated permissions) so operators can pick only the telemetry they need and feed structured output into SIEMs, CMDBs, or incident playbooks while minimizing unnecessary exposure using over **43** (hardware/system, network, and privilege‑escalation different reconnaissance tools).

### Hardware & System

This module forms the foundation of the tool’s host-level inspection capabilities, offering a comprehensive view of a system’s **physical** and **software environment**. It gathers critical data such as the operating system and kernel version, installed packages, loaded drivers, firmware and BIOS information, CPU and GPU specs, available storage, connected USB and display devices, and peripheral interfaces like Wi-Fi adapters. It also collects environmental context like timezone and keyboard layout, and checks for residual user data such as command history, all of which contribute to a **complete profile of the machine's current and historical state.**

Invaluable in both proactive hardening and reactive triage scenarios, can provide an immediate, high-fidelity snapshot that helps validate system baselines, detect unapproved software or hardware changes, verify patch coverage, and assess overall host posture. During an investigation, it allows analysts to rapidly understand what kind of machine they’re dealing with—what drivers are present, what’s connected, what could be exploited, and whether anything looks out of place at a glance.

<details>
<summary></summary>
<a href="https://ibb.co/CxqHRqS"><img src="https://i.ibb.co/5qdRbdJ/hardware1.png" alt="hardware1" border="0"></a>
</details>

### Network & Interfaces

This module can be used to build a focused picture of how a host sits on and interacts with the network. If selected, it can enumerate available interfaces, report MAC addresses and basic link state, and show routing and ARP entries so you can see which subnets and neighbors are reachable from that host. If the operator chooses that option, it can also summarize DNS/resolver settings and firewall/NAT posture and list listening ports and local service bindings to **highlight exposed attack surface**. When deeper diagnostics are explicitly chosen and authorized, it can collect interface statistics, enumerate local devices, or run short, gated packet captures for troubleshooting — these capabilities are optional and should only be enabled when needed. If live traffic capture is selected and permitted, the module can sniff TCP and UDP traffic and capture HTTP/HTTPS transactions in real time from the host for diagnostic or investigative purposes; HTTPS payloads remain protected by encryption unless proper decryption keys or authorized interception are available, and these live‑capture features require explicit elevated permission and audit logging.

These selective checks can speed up audits and incident triage: if selected during an alert, the module can quickly reveal whether a host is on a segmented network, whether resolvers or routes look abnormal, or which services are accepting external connections, helping prioritization and containment. Because outputs are modular, teams can pick just the information they need and pipe structured results into SIEMs or CMDBs without collecting unnecessary data.

<details>
<summary></summary>
<a href="https://ibb.co/nqMLLyR0"><img src="https://i.ibb.co/vC4jjWDB/network1.png" alt="" border="0"></a>
</details>

### Privilage Escalation Reconnaissance

The Privilege Escalation Reconnaissance module is a targeted, on‑demand examiner of a host’s privilege and authentication posture — it can surface the kinds of permission, configuration, and artifact details an administrator would want to know when hardening systems or investigating a suspected compromise, and it can be run selectively so teams only collect what they need. If selected, the module can inspect sudo configuration and policy lines to highlight overly permissive rules, check for files and directories that are writable by non‑privileged users (including service configs, plugin directories, and common configuration paths), and enumerate setuid/setgid binaries or other unusual file permissions that might enable local escalation. It can also report whether protected stores (like shadow files, key material, or Kerberos caches) are accessible under the current identity, flag writable cron or service config entries, and identify root‑owned listening sockets or insecure shared library/config permissions that could be abused via LD_PRELOAD-style injection. When chosen, deeper probes can examine container and orchestration runtime visibility, search for legacy backup or temp files that might contain credentials, and summarize PAM/SSSD/auth configuration to reveal risky authentication fallbacks — all of which are optional and should be enabled only when needed.

For blue teams, these selective checks can rapidly **prioritize remediation by pointing to the highest‑impact misconfigurations**: a writable service config or a sloppy sudo rule is often a faster fix than chasing lower‑probability vectors. During investigations, the module can narrow the scope of privilege escalation paths to verify whether a compromised account could realistically obtain root or interact with privileged services. Because these findings are produced in a structured, audited format, they can be fed into patching and hardening playbooks, tracked in remediation tickets, or used to produce phased mitigation plans.

<details>
<summary></summary>
<a href="https://ibb.co/gL0ntxBg"><img src="https://i.ibb.co/HfcJGjkg/privesc1.png" alt="" border="0"></a>
</details>

### Disclosure

This tool is provided for **authorized security, inventory, and defensive use only**. Do not deploy or run it against systems, networks, or services for which you do not have explicit permission. By using this software you confirm you have the right to perform reconnaissance on the target and will comply with all applicable laws and policies.




