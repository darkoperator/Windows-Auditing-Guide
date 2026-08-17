# Workstation Auditing Guide

Applies to domain-joined and standalone Windows 10/11 workstations. For Windows Server, see [`guides/server-baseline.md`](server-baseline.md); for domain controllers, see [`guides/domain-controller.md`](domain-controller.md).

## Scope

"Workstation" here means end-user Windows 10 and Windows 11 desktops and laptops — the machines people actually sit at (or remote into) to do their jobs, as distinct from servers or domain controllers. There are usually far more of them than any other role, they run the widest variety of third-party software, they're where phishing payloads and malicious documents first execute, and they're carried outside the network perimeter (or exposed to it via RDP). Despite that exposure, workstations are frequently the least-monitored tier in an environment — audit policy defaults are permissive, PowerShell/script logging is often left off, and event forwarding is deployed to servers first, if at all. That combination (largest attack surface, weakest baseline visibility) makes workstations the highest-value place to close logging gaps: most initial-access and execution techniques (phishing attachments, malicious macros, LOLBins, credential dumping from LSASS, USB-borne malware) land here first, before an attacker ever pivots toward a server or domain controller.

## Baseline settings

The baseline tier is the minimum viable audit configuration: enough to catch logons, account/group changes, process creation, and tampering with the audit trail itself, without generating so much volume that a small team can't keep up.

[`settings/subcategories/workstation-baseline.csv`](../settings/subcategories/workstation-baseline.csv) is an `auditpol /backup`-format file enabling these Advanced Audit Policy subcategories (all under the `System` policy target, restorable directly with `auditpol /restore /file:settings/subcategories/workstation-baseline.csv`):

- **Account Logon**: Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations
- **Account Management**: Computer Account Management, Security Group Management, User Account Management
- **Detailed Tracking**: Process Creation
- **Logon/Logoff**: Account Lockout, Logoff, Logon, Special Logon
- **Policy Change**: Audit Policy Change
- **Privilege Use**: Sensitive Privilege Use
- **System**: Security State Change, Security System Extension, System Integrity

Alongside the `auditpol` subcategories, [`settings/registry-settings.csv`](../settings/registry-settings.csv) has rows with `Role = all` or `Role = workstation` and `Tier = baseline`. These are Administrative Templates values `auditpol` can't set, applied via `reg.exe` or Group Policy instead — on workstations this covers:

- PowerShell Module Logging and Script Block Logging (`EnableModuleLogging`, `ModuleNames = *`, `EnableScriptBlockLogging`)
- Including the command line in process creation events (`ProcessCreationIncludeCmdLine_Enabled`) — without this, event 4688 shows the process image but not its arguments
- Forcing subcategory audit policy to override legacy category-level policy (`SCENoApplyLegacyAuditPolicy`)
- Application, Security, and System event log maximum size (4 GB) and retention (do not overwrite)

See [`settings/README.md`](../settings/README.md) for exactly how to apply either file (`auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback).

## Advanced settings

Beyond baseline, add [`settings/subcategories/workstation-advanced.csv`](../settings/subcategories/workstation-advanced.csv), which layers on top of every baseline subcategory (it's a superset, not a delta — restoring it alone gives you baseline + advanced in one step) plus these additional subcategories:

- **Account Management**: Other Account Management Events
- **Detailed Tracking**: DPAPI Activity
- **Object Access**: File System, Handle Manipulation, Registry, Kernel Object, File Share, Detailed File Share
- **Policy Change**: Authentication Policy Change, MPSSVC Rule-Level Policy Change, Other Policy Change Events
- **Logon/Logoff**: Other Logon/Logoff Events

This tier is what makes object-access events (4656/4658/4663/4657/5140/5145), DPAPI activity, and detailed file-share access visible — meaningfully higher log volume, so plan storage/SIEM ingest accordingly before turning it on fleet-wide.

The corresponding `Tier = advanced` row in [`settings/registry-settings.csv`](../settings/registry-settings.csv) for this role enables PowerShell Transcription (`EnableTranscripting`) — optional, and only useful if you also configure an `OutputDirectory` to centralize the transcript files; otherwise they sit locally on each workstation.

## Event table

Every event in [`event-catalog/events.json`](../event-catalog/events.json) whose `applicableRoles` includes `workstation`, sorted by Event ID. See [`event-catalog/full-table.md`](../event-catalog/full-table.md) for the complete cross-role catalog.

| Event ID | Log Source | Description | Criticality | MITRE Technique(s) |
|----------|-----------|-------------|-------------|---------------------|
| 8 | Microsoft-Windows-WMI-Activity/Operational | Error accessing object path | High | T1047 - Windows Management Instrumentation |
| 11 | Microsoft-Windows-WMI-Activity/Operational | Error starting WMI service | High | T1047 - Windows Management Instrumentation |
| 19 | Microsoft-Windows-WMI-Activity/Operational | WMI subscription error | High | T1047 - Windows Management Instrumentation |
| 20 | Microsoft-Windows-WMI-Activity/Operational | WMI subscription error | High | T1047 - Windows Management Instrumentation |
| 21 | Terminal-Services-LocalSessionManager/Operational | RDP Session Logon Succeeded | High | T1021.001 - Remote Desktop Protocol |
| 22 | Terminal-Services-LocalSessionManager/Operational | RDP Shell Start Notification | Medium | T1021.001 - Remote Desktop Protocol |
| 23 | Terminal-Services-LocalSessionManager/Operational | RDP Session Logoff | Medium | T1021.001 - Remote Desktop Protocol |
| 24 | Terminal-Services-LocalSessionManager/Operational | RDP Session Disconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 25 | Terminal-Services-LocalSessionManager/Operational | RDP Session Reconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 39 | Terminal-Services-LocalSessionManager/Operational | RDP Session Disconnected by Admin | High | T1021.001 - Remote Desktop Protocol |
| 40 | Terminal-Services-LocalSessionManager/Operational | RDP Session Disconnected by Reason Code | Medium | T1021.001 - Remote Desktop Protocol |
| 131 | Terminal-Services-RemoteConnectionManager/Operational | RDP Connection Attempt | High | T1021.001 - Remote Desktop Protocol |
| 140 | Terminal-Services-RemoteConnectionManager/Operational | RDP Connection Succeeded | High | T1021.001 - Remote Desktop Protocol |
| 403 | Windows PowerShell | PowerShell engine lifecycle | High | T1059.001 - PowerShell |
| 1000 | Application | Application crash | Medium | T1546 - Event Triggered Execution |
| 1002 | Application | Application hang | Medium | T1546 - Event Triggered Execution |
| 1006 | Microsoft-Windows-Windows Defender/Operational | Malware detected | High | T1047 - Windows Management Instrumentation |
| 1007 | Microsoft-Windows-Windows Defender/Operational | Malware remediation | High | T1047 - Windows Management Instrumentation |
| 1008 | Microsoft-Windows-Windows Defender/Operational | Malware failed remediation | High | T1047 - Windows Management Instrumentation |
| 1015 | Microsoft-Windows-Windows Defender/Operational | Suspicious behavior detection | High | T1047 - Windows Management Instrumentation |
| 1100 | Security | Event logging service shut down | High | T1562.002 - Disable Windows Event Logging |
| 1102 | Security | Audit log cleared | High | T1070.001 - Clear Windows Event Logs |
| 1104 | Security | Security log full | High | T1562.002 - Disable Windows Event Logging |
| 1116 | Microsoft-Windows-Windows Defender/Operational | Detection source | High | T1047 - Windows Management Instrumentation |
| 1117 | Microsoft-Windows-Windows Defender/Operational | AV component started | Medium | T1562.001 - Disable or Modify Tools |
| 1118 | Microsoft-Windows-Windows Defender/Operational | AV component stopped | High | T1562.001 - Disable or Modify Tools |
| 1149 | Terminal-Services-RemoteConnectionManager/Operational | User authentication succeeded | High | T1021.001 - Remote Desktop Protocol |
| 2003 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 2004 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 2005 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 2006 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall rule group added | High | T1562.004 - Disable or Modify Firewall Rules |
| 2033 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall driver started | Medium | T1562.004 - Disable or Modify Firewall Rules |
| 2034 | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall driver stopped | High | T1562.004 - Disable or Modify Firewall Rules |
| 4103 | Microsoft-Windows-PowerShell/Operational | Module logging | High | T1059.001 - PowerShell |
| 4104 | Microsoft-Windows-PowerShell/Operational | Script block logging | High | T1059.001 - PowerShell |
| 4624 | Security | Successful account logon | High | T1078 - Valid Accounts |
| 4625 | Security | Failed account logon | High | T1110 - Brute Force |
| 4634 | Security | Account logoff | Medium | T1078 - Valid Accounts |
| 4647 | Security | User initiated logoff | Low | T1078 - Valid Accounts |
| 4648 | Security | Logon with explicit credentials | High | T1078 - Valid Accounts; T1550.002 - Pass the Hash |
| 4656 | Security | Handle to an object requested | High | T1003.001 - LSASS Memory |
| 4657 | Security | Registry value modified | High | T1112 - Modify Registry |
| 4658 | Security | Handle to object closed | Medium | T1003.001 - LSASS Memory |
| 4660 | Security | Object deleted | High | T1485 - Data Destruction |
| 4663 | Security | Object access attempt | High | T1003 - OS Credential Dumping; T1003.001 - LSASS Memory |
| 4670 | Security | Permissions on object changed | High | T1222 - File and Directory Permissions Modification |
| 4672 | Security | Special privileges assigned to new logon | High | T1078 - Valid Accounts; T1078.003 - Local Accounts; T1548 - Abuse Elevation Control Mechanism |
| 4688 | Security | Process creation | High | T1059 - Command and Scripting Interpreter |
| 4689 | Security | Process termination | Medium | T1059 - Command and Scripting Interpreter |
| 4696 | Security | Primary token assigned to process | High | T1134 - Access Token Manipulation |
| 4697 | Security | Service installation | High | T1543.003 - Windows Service |
| 4698 | Security | Scheduled task created | High | T1053.005 - Scheduled Task |
| 4699 | Security | Scheduled task deleted | High | T1053.005 - Scheduled Task |
| 4700 | Security | Scheduled task enabled | Medium | T1053.005 - Scheduled Task |
| 4701 | Security | Scheduled task disabled | Medium | T1053.005 - Scheduled Task |
| 4702 | Security | Scheduled task updated | High | T1053.005 - Scheduled Task |
| 4719 | Security | System audit policy changed | High | T1562.002 - Disable Windows Event Logging |
| 4720 | Security | User account created | High | T1136 - Create Account |
| 4722 | Security | User account enabled | High | T1078 - Valid Accounts |
| 4723 | Security | Password change attempt | High | T1098 - Account Manipulation |
| 4724 | Security | Password reset attempt | High | T1098 - Account Manipulation |
| 4725 | Security | User account disabled | High | T1098 - Account Manipulation |
| 4726 | Security | User account deleted | High | T1531 - Account Access Removal |
| 4728 | Security | Member added to security-enabled global group | High | T1098 - Account Manipulation |
| 4729 | Security | Member removed from security-enabled global group | High | T1098 - Account Manipulation |
| 4732 | Security | Member added to security-enabled local group | High | T1098 - Account Manipulation |
| 4733 | Security | Member removed from security-enabled local group | High | T1098 - Account Manipulation |
| 4738 | Security | User account changed | High | T1098 - Account Manipulation |
| 4740 | Security | User account locked out | High | T1110 - Brute Force |
| 4767 | Security | User account unlocked | Medium | T1078 - Valid Accounts; T1098 - Account Manipulation |
| 4776 | Security | Credential validation | High | T1110 - Brute Force |
| 4778 | Security | Session reconnected to window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4779 | Security | Session disconnected from window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4800 | Security | Workstation locked | Low | T1078 - Valid Accounts |
| 4801 | Security | Workstation unlocked | Low | T1078 - Valid Accounts |
| 4802 | Security | Screen saver invoked | Low | T1078 - Valid Accounts |
| 4803 | Security | Screen saver dismissed | Low | T1078 - Valid Accounts |
| 4946 | Security | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 4947 | Security | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 4948 | Security | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 4950 | Security | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules |
| 5001 | Microsoft-Windows-Windows Defender/Operational | Real-time protection disabled | High | T1562.001 - Disable or Modify Tools |
| 5004 | Microsoft-Windows-Windows Defender/Operational | Real-time protection configuration changed | High | T1562.001 - Disable or Modify Tools |
| 5007 | Microsoft-Windows-Windows Defender/Operational | Antimalware platform configuration changed | High | T1562.001 - Disable or Modify Tools |
| 5010 | Microsoft-Windows-Windows Defender/Operational | Scanning disabled by tamper protection | High | T1562.001 - Disable or Modify Tools |
| 5140 | Security | Network share accessed | High | T1021.002 - SMB/Windows Admin Shares |
| 5142 | Security | Network share object added | High | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Security | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |
| 5156 | Security | Windows Filtering Platform allowed connection | Medium | T1047 - Windows Management Instrumentation; T1562.004 - Disable or Modify Firewall Rules |
| 5857 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation |
| 5858 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation |
| 5859 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation |
| 5860 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Consumer Error | High | T1047 - Windows Management Instrumentation |
| 5861 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Consumer Warning | Medium | T1047 - Windows Management Instrumentation |
| 6416 | Security | A new external device was recognized | High | T1200 - Hardware Additions |
| 6419 | Security | Device installation request | Medium | T1200 - Hardware Additions |
| 6420 | Security | Device disabled | Medium | T1200 - Hardware Additions |
| 6421 | Security | Device installation allowed | Medium | T1200 - Hardware Additions |
| 6422 | Security | Device install enabled | Medium | T1200 - Hardware Additions |
| 6423 | Security | Installation forbidden by policy | Medium | T1200 - Hardware Additions |
| 6424 | Security | Device installation allowed | Medium | T1200 - Hardware Additions |
| 7022 | System | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7026 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7031 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | System | Service start type changed | High | T1543.003 - Windows Service; T1562 - Impair Defenses |
| 7045 | System | New service installed | High | T1543.003 - Windows Service |
| 11707 | Application | Install completed successfully | Medium | T1204 - User Execution |
| 11708 | Application | Install failed | Medium | T1204 - User Execution |
| 11724 | Application | Application removal | Medium | T1204 - User Execution |

## Role-specific notes

Priorities specific to workstations, condensed from operational experience monitoring end-user endpoints (not redundant with what the event table above already shows):

- **Command-line visibility on process creation is non-negotiable.** Event 4688 alone shows only the parent/child image paths; without `ProcessCreationIncludeCmdLine_Enabled` (baseline registry setting, above) you lose the arguments that distinguish a benign `powershell.exe` launch from an encoded, obfuscated one. Pair 4688 with 4103/4104 (PowerShell module and script block logging) — together they cover the two most common workstation execution paths for both legitimate admin activity and living-off-the-land attacks.
- **LSASS access is a top-tier workstation detection.** Events 4656/4658/4663 against the `lsass.exe` process handle are one of the highest-signal indicators of credential dumping (Mimikatz and similar tools) on an endpoint — prioritize alerting on these over treating them as routine object-access noise.
- **Removable media and hardware additions matter more here than on servers.** Workstations are where USB-borne malware and unauthorized peripherals (rogue Wi-Fi adapters, HID-emulating devices) actually get plugged in. Events 6416/6419–6424 cover device recognition and installation policy; review 6423 (installation forbidden by policy) as a sign someone is trying to bypass device-control policy.
- **Security-tool tampering is an early ransomware/intrusion indicator.** Defender events (5001 real-time protection disabled, 5010 tamper-protection block, 1117/1118 AV component stop) and firewall events (2003–2006, 2034, 4946–4950) should be treated as high-priority alerts, not routine configuration-change logging — attackers routinely disable or reconfigure endpoint protection immediately before or after landing.
- **RDP session events double as lateral-movement telemetry.** On workstations, inbound RDP (131/140/1149/21–25/39/40) is often unexpected — most end users don't receive RDP sessions from other hosts. Baseline the normal pattern (help-desk remote assistance, IT admin access) so any deviation stands out.
- **Session-state events (4800–4803, workstation lock/unlock/screen-saver) are low-severity individually** but valuable for correlating physical presence against account activity — e.g., a 4624 successful logon or 4688 process creation on a workstation currently showing as locked (4800) is worth investigating.
- **Audit-log tampering detection is not optional at any tier.** 1102 (audit log cleared), 1100 (logging service shut down), and 4719 (audit policy changed) should be forwarded off-box and alerted on immediately — a workstation clearing its own Security log is one of the strongest single indicators of an attacker cleaning up after themselves.
- **Scheduled tasks and service installation are common persistence mechanisms on workstations**, not just servers — 4698/4699/4702 (scheduled task create/delete/update) and 4697/7045 (service installed) deserve the same scrutiny here as in the server guide, since a compromised workstation account with local admin rights can establish persistence identically to a server.
