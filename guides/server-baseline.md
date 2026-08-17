# Server Baseline Auditing Guide

Applies to general-purpose, domain-joined Windows Server 2016+ member servers — file servers, application servers, print servers, and similar workloads that are neither domain controllers nor certificate authorities. For Windows 10/11 endpoints, see [`guides/workstation.md`](workstation.md); for domain controllers, see [`guides/domain-controller.md`](domain-controller.md); for certificate authorities, see [`guides/certificate-authority.md`](certificate-authority.md).

## Scope

"Server baseline" here means the broad middle tier of the server fleet: member servers running file shares, line-of-business applications, web/app services, and infrastructure roles, as distinct from domain controllers (which hold the domain database and are covered by their own guide) and certificate authorities (which have their own certificate-services-specific event set). There are usually more of these than domain controllers or CAs, they hold the data attackers actually want — file shares, databases, application data — and they're where lateral movement techniques land after initial access on a workstation (RDP, SMB/admin-share access, remote service creation, WMI). Because they're treated as "just infrastructure," server audit policy is frequently set once at build time and never revisited, and object-access auditing on the file shares those servers exist to serve is often skipped entirely because of the volume it generates. That combination — high-value data, well-known lateral-movement techniques, and inconsistent audit coverage — makes a consistent baseline across the server fleet as important as workstation coverage, not an afterthought bolted on for compliance.

## Baseline settings

The baseline tier is the minimum viable audit configuration: enough to catch logons, account/group changes, process creation, and tampering with the audit trail itself, without generating so much volume that a small team can't keep up.

[`settings/subcategories/server-baseline.csv`](../settings/subcategories/server-baseline.csv) is an `auditpol /backup`-format file enabling these Advanced Audit Policy subcategories (all under the `System` policy target, restorable directly with `auditpol /restore /file:settings/subcategories/server-baseline.csv`):

- **Account Logon**: Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations
- **Account Management**: Computer Account Management, Security Group Management, User Account Management
- **Detailed Tracking**: Process Creation
- **Logon/Logoff**: Account Lockout, Logoff, Logon, Special Logon
- **Policy Change**: Audit Policy Change
- **Privilege Use**: Sensitive Privilege Use
- **System**: Security State Change, Security System Extension, System Integrity

This is the same set of 16 subcategories as the workstation baseline — the underlying audit-policy configuration for logon/account/process/policy-tampering visibility doesn't actually change between a desktop and a member server, only which role a machine is given determines whether it's applied. See `settings/subcategories/workstation-baseline.csv` for confirmation; the two files are identical in content.

Alongside the `auditpol` subcategories, [`settings/registry-settings.csv`](../settings/registry-settings.csv) has rows with `Role = all` and `Tier = baseline`. These are Administrative Templates values `auditpol` can't set, applied via `reg.exe` or Group Policy instead — on servers this covers:

- PowerShell Module Logging and Script Block Logging (`EnableModuleLogging`, `ModuleNames = *`, `EnableScriptBlockLogging`)
- Including the command line in process creation events (`ProcessCreationIncludeCmdLine_Enabled`) — without this, event 4688 shows the process image but not its arguments
- Forcing subcategory audit policy to override legacy category-level policy (`SCENoApplyLegacyAuditPolicy`)
- Application, Security, and System event log maximum size (4 GB) and retention (do not overwrite)

See [`settings/README.md`](../settings/README.md) for exactly how to apply either file (`auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback).

## Advanced settings

Beyond baseline, add [`settings/subcategories/server-advanced.csv`](../settings/subcategories/server-advanced.csv), which layers on top of every baseline subcategory (it's a superset, not a delta — restoring it alone gives you baseline + advanced in one step) plus these additional subcategories:

- **Account Management**: Other Account Management Events
- **Detailed Tracking**: DPAPI Activity
- **Object Access**: File System, Handle Manipulation, Registry, Kernel Object, File Share, Detailed File Share
- **Policy Change**: Authentication Policy Change, MPSSVC Rule-Level Policy Change, Other Policy Change Events
- **Logon/Logoff**: Other Logon/Logoff Events

This is where server auditing earns its keep: File Share and Detailed File Share are what make 5140/5142/5143/5144/5145 (share accessed/added/modified/deleted/checked) visible at all, which matters far more on a file server hosting shared data than it does on a single-user workstation. Object Access more broadly (File System, Registry, Handle Manipulation, Kernel Object) also drives 4656/4657/4658/4660/4663 — meaningfully higher log volume once turned on for a busy file or application server, so plan storage/SIEM ingest and, if needed, targeted SACLs on specific file shares before turning this on fleet-wide rather than auditing every object on every volume.

The corresponding `Tier = advanced` row in [`settings/registry-settings.csv`](../settings/registry-settings.csv) for this role enables PowerShell Transcription (`EnableTranscripting`) — optional, and only useful if you also configure an `OutputDirectory` to centralize the transcript files; otherwise they sit locally on each server.

Beyond what `auditpol` and the registry rows above cover, the original server GPO configuration guide also calls out hardening WinRM (disabling Basic/CredSSP/unencrypted-traffic, requiring channel-binding token hardening) and RDS Session Host settings (Network Level Authentication, high encryption level) — those are remote-management/RDP hardening controls rather than audit-logging settings, so they're out of scope for this settings-data-driven guide, but worth applying alongside the audit policy above on any server that accepts inbound WinRM or RDP.

## Event table

Every event in [`event-catalog/events.json`](../event-catalog/events.json) whose `applicableRoles` includes `server`, sorted by Event ID. See [`event-catalog/full-table.md`](../event-catalog/full-table.md) for the complete cross-role catalog.

| Event ID | Log Source | Description | Criticality | MITRE Technique(s) |
|----------|-----------|-------------|-------------|---------------------|
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
| 1100 | Security | Event logging service shut down | High | T1562.002 - Disable Windows Event Logging |
| 1102 | Security | Audit log cleared | High | T1070.001 - Clear Windows Event Logs |
| 1104 | Security | Security log full | High | T1562.002 - Disable Windows Event Logging |
| 1149 | Terminal-Services-RemoteConnectionManager/Operational | User authentication succeeded | High | T1021.001 - Remote Desktop Protocol |
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
| 4768 | Security | Kerberos TGT requested | High | T1558.003 - Kerberoasting |
| 4769 | Security | Kerberos service ticket requested | High | T1558.003 - Kerberoasting |
| 4771 | Security | Kerberos pre-authentication failed | High | T1110 - Brute Force |
| 4776 | Security | Credential validation | High | T1110 - Brute Force |
| 4778 | Security | Session reconnected to window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4779 | Security | Session disconnected from window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4905 | Security | Security event source unregistered | High | T1562.002 - Disable Windows Event Logging |
| 4907 | Security | Auditing settings changed on object | High | T1562.002 - Disable Windows Event Logging |
| 4912 | Security | Per-user audit policy changed | High | T1562.002 - Disable Windows Event Logging |
| 4946 | Security | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 4947 | Security | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 4948 | Security | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 4950 | Security | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules |
| 5140 | Security | Network share accessed | High | T1021.002 - SMB/Windows Admin Shares |
| 5142 | Security | Network share object added | High | T1021.002 - SMB/Windows Admin Shares |
| 5143 | Security | Network share object modified | High | T1021.002 - SMB/Windows Admin Shares |
| 5144 | Security | Network share object deleted | High | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Security | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |
| 5156 | Security | Windows Filtering Platform allowed connection | Medium | T1047 - Windows Management Instrumentation; T1562.004 - Disable or Modify Firewall Rules |
| 5857 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation |
| 5858 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation |
| 5859 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation |
| 5860 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Consumer Error | High | T1047 - Windows Management Instrumentation |
| 5861 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Consumer Warning | Medium | T1047 - Windows Management Instrumentation |
| 6416 | Security | A new external device was recognized | High | T1200 - Hardware Additions |
| 7022 | System | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7026 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7031 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | System | Service start type changed | High | T1543.003 - Windows Service; T1562 - Impair Defenses |
| 7045 | System | New service installed | High | T1543.003 - Windows Service |

## Role-specific notes

Priorities specific to general-purpose member servers, condensed from operational experience monitoring file/application server fleets (not redundant with what the event table above already shows):

- **File share activity is the headline reason to turn on Advanced settings here.** Unlike the workstation guide, a server's Object Access / File Share / Detailed File Share subcategories are usually monitoring data other people depend on, not one person's local disk. 5140 (share accessed) is high-volume and mostly noise; 5143/5144 (share object modified/deleted) and 4660/4663 against sensitive shares are the higher-signal events — consider scoping SACLs to specific high-value shares (finance, HR, engineering source, backups) rather than auditing every share equally.
- **Kerberos service ticket events matter on member servers, not just domain controllers.** 4769 (service ticket requested) and 4768 (TGT requested) are logged wherever the authentication happens, but on a server hosting a service account (SQL, IIS app pool, scheduled task) a spike of 4769 requests against that service's SPN is the classic signature of Kerberoasting — an offline password-cracking attack against service account tickets. Baseline the normal ticket-request volume per service account so a spike stands out.
- **Object-access-auditing tampering (4907/4912) is a server-specific tell.** An attacker (or a careless admin) removing the SACL from a sensitive folder so file access stops generating 4663 events shows up as 4907 (auditing settings changed on object); treat it with the same urgency as 4719 (audit policy changed) and 1102 (audit log cleared) — all three are ways to blind the same detection.
- **Service installation and scheduled tasks are the primary server persistence mechanisms.** 4697 (service installed) / 7045 (new service installed) and 4698/4699/4702 (scheduled task create/delete/update) deserve first-class alerting on servers — lateral movement via PsExec-style remote service creation or `schtasks` is one of the most common ways an attacker who has admin credentials pivots from workstation to server and establishes persistence.
- **RDP and remote-management access should be treated as administrative activity, not routine.** 131/140/1149/21–25/39/40 (RDP) on a server is expected to come from a known, small set of admin accounts and jump hosts; anything outside that pattern (a service account, a non-admin user, an unfamiliar source) is worth investigating immediately. The source GPO guide also calls for hardening WinRM (disable Basic/CredSSP/unencrypted auth, require Network Level Authentication on RDS) alongside this event coverage — logging remote access without also hardening how it's reached only gets you half the picture.
- **Command-line visibility and PowerShell logging carry over unchanged from workstations.** 4688 with `ProcessCreationIncludeCmdLine_Enabled` (baseline registry setting, above) plus 4103/4104 (PowerShell module/script block logging) are just as critical on a server as an endpoint — arguably more so, since a compromised server often has direct access to production data and higher-privilege service accounts than any individual workstation does.
- **Audit-log tampering detection is not optional at any tier.** 1102 (audit log cleared), 1100 (logging service shut down), 4719 (audit policy changed), and the object-level equivalents 4905/4907/4912 above should be forwarded off-box and alerted on immediately — a server clearing its own Security log, especially one hosting shared data or a domain-facing service, is one of the strongest single indicators of an attacker cleaning up after themselves.
