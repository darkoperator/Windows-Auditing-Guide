# Domain Controller Auditing Guide

Applies to Active Directory Domain Controllers running Windows Server 2016+. For Windows 10/11 endpoints, see [`guides/workstation.md`](workstation.md); for general-purpose member servers, see [`guides/server-baseline.md`](server-baseline.md); for certificate authorities, see [`guides/certificate-authority.md`](certificate-authority.md).

## Scope

"Domain controller" here means machines running Active Directory Domain Services (AD DS) — the servers holding the domain's directory database (NTDS.dit), replicating it to every other DC in the domain, and answering the Kerberos/NTLM authentication and LDAP directory requests every other machine in the domain depends on. There are usually only a handful of them, often single digits even in large environments, but compromising just one is functionally equivalent to compromising the entire domain: an attacker with control of a DC can extract every credential in the domain (DCSync), forge Kerberos tickets that never expire (Golden Ticket, via the krbtgt account), and rewrite Group Policy or AD object permissions across the whole environment. Because of that blast radius, domain controllers can't be treated as "just another server" the way the server-baseline guide's member servers can — the baseline/advanced split that lets other roles defer high-volume auditing until they can afford the ingest cost is a much weaker justification here; DCs are worth the storage and SIEM cost of full auditing from day one. The two AD-specific subcategories called out below (Directory Service Access, Directory Service Changes) exist only on this role, because domain controllers are the only machines with a directory database to audit access against.

## Baseline settings

The baseline tier is the minimum viable audit configuration: enough to catch logons, account/group changes, process creation, tampering with the audit trail itself, and — specific to this role — reads and writes against the directory database, without generating so much volume that a small team can't keep up.

[`settings/subcategories/domain-controller-baseline.csv`](../settings/subcategories/domain-controller-baseline.csv) is an `auditpol /backup`-format file enabling these Advanced Audit Policy subcategories (all under the `System` policy target, restorable directly with `auditpol /restore /file:settings/subcategories/domain-controller-baseline.csv`):

- **Account Logon**: Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations
- **Account Management**: Computer Account Management, Security Group Management, User Account Management
- **Detailed Tracking**: Process Creation
- **DS Access**: Directory Service Access, Directory Service Changes
- **Logon/Logoff**: Account Lockout, Logoff, Logon, Special Logon
- **Policy Change**: Audit Policy Change
- **Privilege Use**: Sensitive Privilege Use
- **System**: Security State Change, Security System Extension, System Integrity

This is the same 16-subcategory core used in the workstation and server baselines, plus two subcategories that are **specific to domain controllers and don't exist for any other role in this guide set**: **Directory Service Access** and **Directory Service Changes**, grouped under the **DS Access** category. These two are what generate event 4662 (operation performed on an AD object) and the 5136/5137/5138/5139/5141 directory-service object change events in the event table below — visibility into reads and writes against the actual AD database (users, groups, GPOs, OUs, trust objects, AdminSDHolder). No other role audited in this repository has anything under DS Access, because no other role hosts a directory database; enabling these two subcategories is the one piece of baseline configuration that is genuinely unique to this guide.

Alongside the `auditpol` subcategories, [`settings/registry-settings.csv`](../settings/registry-settings.csv) has rows with `Role = all` or `Role = domain-controller` and `Tier = baseline`. Every current row in that file is `Role = all` — the same Administrative Templates values apply here as on workstations and servers; there is no domain-controller-specific baseline registry row yet, which is expected rather than a gap:

- PowerShell Module Logging and Script Block Logging (`EnableModuleLogging`, `ModuleNames = *`, `EnableScriptBlockLogging`)
- Including the command line in process creation events (`ProcessCreationIncludeCmdLine_Enabled`) — without this, event 4688 shows the process image but not its arguments
- Forcing subcategory audit policy to override legacy category-level policy (`SCENoApplyLegacyAuditPolicy`)
- Application, Security, and System event log maximum size (4 GB) and retention (do not overwrite)

See [`settings/README.md`](../settings/README.md) for exactly how to apply either file (`auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback).

## Advanced settings

Beyond baseline, add [`settings/subcategories/domain-controller-advanced.csv`](../settings/subcategories/domain-controller-advanced.csv), which layers on top of every baseline subcategory (it's a superset, not a delta — restoring it alone gives you baseline + advanced in one step, including the two DS Access subcategories above) plus these additional subcategories:

- **Account Management**: Other Account Management Events
- **Detailed Tracking**: DPAPI Activity
- **Object Access**: File System, Handle Manipulation, Registry, Kernel Object, File Share, Detailed File Share
- **Policy Change**: Authentication Policy Change, MPSSVC Rule-Level Policy Change, Other Policy Change Events
- **Logon/Logoff**: Other Logon/Logoff Events

This is the same 12-subcategory advanced layer used in the workstation and server guides, applied on top of the DC-specific baseline above (18 baseline subcategories + 12 advanced = 30 total rows in the file). It's what makes object-access events (4656/4658/4663/4657/4660/5140/5142/5145) and detailed file-share access visible — notably including SYSVOL, the network share every Group Policy Object lives on and replicates from, which is itself subject to File Share/Detailed File Share auditing just like any other share. As with the other roles, this tier is meaningfully higher log volume, so plan storage/SIEM ingest accordingly — though per the Scope note above, domain controllers are the role where deferring that cost is least defensible.

The corresponding `Tier = advanced` row in [`settings/registry-settings.csv`](../settings/registry-settings.csv) for this role enables PowerShell Transcription (`EnableTranscripting`) — optional, and only useful if you also configure an `OutputDirectory` to centralize the transcript files; otherwise they sit locally on each DC.

A handful of subcategories the CSVs above don't cover are also worth calling out, since the events they gate appear in the event table below: the `Other Object Access Events` subcategory (Object Access — needed for scheduled-task events 4698-4702) isn't included in the CSVs above — enable it manually if you want this coverage: `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`. The `Filtering Platform Connection` subcategory (Object Access — needed for events 5156/5157, allowed/blocked connection logging) isn't covered either: `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable`. Nor is `Filtering Platform Packet Drop` (Object Access — needed for events 5152/5153/5155, dropped-packet logging): `auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable`.

## Event table

Every event in [`event-catalog/events.json`](../event-catalog/events.json) whose `applicableRoles` includes `domain-controller`, sorted by Event ID. See [`event-catalog/full-table.md`](../event-catalog/full-table.md) for the complete cross-role catalog.

| Event ID | Log Source | Description | Criticality | MITRE Technique(s) |
|----------|-----------|-------------|-------------|---------------------|
| 21 | Terminal-Services-LocalSessionManager/Operational | RDP Session Logon Succeeded | High | T1021.001 - Remote Desktop Protocol |
| 22 | Terminal-Services-LocalSessionManager/Operational | RDP Shell Start Notification | Medium | T1021.001 - Remote Desktop Protocol |
| 23 | Terminal-Services-LocalSessionManager/Operational | RDP Session Logoff | Medium | T1021.001 - Remote Desktop Protocol |
| 24 | Terminal-Services-LocalSessionManager/Operational | RDP Session Disconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 25 | Terminal-Services-LocalSessionManager/Operational | RDP Session Reconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 403 | Windows PowerShell | PowerShell engine lifecycle | High | T1059.001 - PowerShell |
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
| 4662 | Directory Service | Operation performed on Active Directory object | High | T1087.002 - Domain Account Discovery |
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
| 4756 | Security | Member added to security-enabled universal group | Medium | T1098 - Account Manipulation |
| 4757 | Security | Member removed from security-enabled universal group | Medium | T1098 - Account Manipulation |
| 4767 | Security | User account unlocked | Medium | T1078 - Valid Accounts; T1098 - Account Manipulation |
| 4768 | Security | Kerberos TGT requested | High | T1558.003 - Kerberoasting |
| 4769 | Security | Kerberos service ticket requested | High | T1558.003 - Kerberoasting |
| 4771 | Security | Kerberos pre-authentication failed | High | T1110 - Brute Force |
| 4776 | Security | Credential validation | High | T1110 - Brute Force |
| 4778 | Security | Session reconnected to window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4779 | Security | Session disconnected from window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4794 | Security | Directory Services Restore Mode admin password set | High | T1098 - Account Manipulation |
| 4946 | Security | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 4947 | Security | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 4948 | Security | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 4950 | Security | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules |
| 4954 | Security | Group policy settings for Windows Firewall changed | High | T1562.004 - Disable/Modify Firewall |
| 4956 | Security | Windows Firewall active profile changed | Medium | T1562.004 - Disable/Modify Firewall |
| 4964 | Security | Special groups assigned to new logon | High | T1078 - Valid Accounts |
| 5024 | Security | Windows Firewall service started | Medium | T1562.004 - Disable/Modify Firewall |
| 5025 | Security | Windows Firewall service stopped | High | T1562.004 - Disable/Modify Firewall |
| 5031 | Security | Application blocked from accepting incoming connections | High | T1562.004 - Disable/Modify Firewall |
| 5136 | Directory Service | Directory Service object modified | High | T1484 - Domain Policy Modification |
| 5137 | Directory Service | Directory Service object created | High | T1484 - Domain Policy Modification |
| 5138 | Directory Service | Directory Service object undeleted | High | T1484 - Domain Policy Modification |
| 5139 | Directory Service | Directory Service object moved | High | T1484 - Domain Policy Modification |
| 5140 | Security | Network share accessed | High | T1021.002 - SMB/Windows Admin Shares |
| 5141 | Directory Service | Directory Service object deleted | High | T1484 - Domain Policy Modification |
| 5142 | Security | Network share object added | High | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Security | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |
| 5152 | Security | Network packet blocked by Windows Filtering Platform | Medium | T1562.004 - Disable/Modify Firewall |
| 5153 | Security | A more restrictive Windows Filtering Platform filter blocked a packet | Medium | T1562.004 - Disable/Modify Firewall |
| 5155 | Security | Windows Filtering Platform blocked an application from listening on a port | High | T1562.004 - Disable/Modify Firewall |
| 5156 | Security | Windows Filtering Platform allowed connection | Medium | T1047 - Windows Management Instrumentation; T1562.004 - Disable or Modify Firewall Rules |
| 5157 | Security | Windows Filtering Platform blocked a connection | Medium | T1562.004 - Disable/Modify Firewall |
| 5857 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation |
| 5858 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation |
| 5859 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation |
| 6005 | System | Event log service started | Medium | T1562 - Impair Defenses |
| 6006 | System | Event log service stopped | Medium | T1562 - Impair Defenses |
| 7022 | System | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7031 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | System | Service start type changed | High | T1543.003 - Windows Service; T1562 - Impair Defenses |
| 7045 | System | New service installed | High | T1543.003 - Windows Service |

## Role-specific notes

Priorities specific to domain controllers, condensed from operational experience monitoring AD DS (not redundant with what the event table above already shows):

- **DCSync and directory replication are the top DC-specific detection priority.** Event 4662 (operation performed on an AD object) carrying the `DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` extended rights is the primary telemetry for DCSync-style credential extraction (Mimikatz `lsadump::dcsync` and equivalents) — a legitimate replication request should only ever originate from another domain controller or an explicitly authorized replication account, so 4662 with those rights sourced from anything else deserves immediate escalation.
- **Kerberoasting and AS-REP roasting are logged here first, not on the servers requesting tickets.** 4769 (service ticket requested) and 4768 (TGT requested) fire on the DC that issues them; a spike of 4769 requests against high-value SPNs, or 4768 requests using weak encryption against accounts with Kerberos pre-authentication disabled, are the classic offline-cracking precursors. The server-baseline guide recommends baselining ticket-request volume per service account as a secondary signal — on the DC it's the authoritative source of that signal, not a downstream echo of it.
- **Directory Service object events are DC-only visibility into changes to the domain's actual configuration.** 5136 (modified), 5137 (created), 5138 (undeleted), 5139 (moved), and 5141 (deleted) cover GPOs, OUs, trust objects, AdminSDHolder, and privileged group definitions — changes here precede changes anywhere else in the domain. None of these events (nor 4662) fire without the two DC-specific DS Access baseline subcategories called out above; skipping those two subcategories silently blinds this entire class of detection.
- **DSRM password reset is a rare, high-signal, DC-specific event.** A Directory Services Restore Mode (DSRM) password change (4794) is legitimate only during planned maintenance windows; outside one, it's a strong indicator of an attacker establishing a local-admin-equivalent backdoor account on the DC that bypasses normal domain authentication.
- **Golden Ticket detection is a correlation exercise across the Kerberos event set, not a single event.** There is no dedicated "forged ticket" event; the practical detection surface is 4768/4769 volume and encryption-type anomalies combined with 4624/4634 logons carrying unusually long ticket lifetimes or originating from accounts that shouldn't be authenticating that way — all pointing back to the krbtgt account's hash being compromised.
- **LSASS access matters more on a DC than anywhere else in the environment.** The workstation and server guides both call out 4656/4658/4663 against `lsass.exe` as high-signal for credential dumping; on a domain controller, LSASS memory holds the krbtgt hash and every cached domain credential, so the identical events here represent a full-domain-compromise risk rather than a single-host one — prioritize DC LSASS alerts above their workstation/server equivalents.
- **Security-enabled group changes need domain-wide scope here, not local scope.** 4728/4729/4732/4733/4756/4757 (global/local/universal group membership changes) and 4964 (special groups assigned to new logon) on a DC cover Domain Admins, Enterprise Admins, and other AD-wide privileged groups — a change here affects every machine in the domain, unlike the equivalent local-group events on a single server.
- **Audit-log tampering detection carries the same non-negotiable priority as the other two guides, with higher stakes.** 1102 (audit log cleared), 1100/6006 (logging service shut down/stopped), and 4719 (audit policy changed) on a domain controller should be forwarded off-box and alerted on immediately — clearing the Security log on a DC is one of the last steps in many domain-compromise playbooks, used to erase evidence of DCSync or Golden Ticket activity before it's discovered.
