# Certificate Authority Auditing Guide

Applies to Windows Server 2016+ machines running the Active Directory Certificate Services (AD CS) Certificate Authority role. For Windows 10/11 endpoints, see [`guides/workstation.md`](workstation.md); for general-purpose member servers, see [`guides/server-baseline.md`](server-baseline.md); for domain controllers, see [`guides/domain-controller.md`](domain-controller.md).

## Scope

"Certificate authority" here means machines running the AD CS Certification Authority role service — the servers that issue, renew, and revoke the X.509 certificates the rest of the environment trusts for TLS, code signing, smart-card logon, and (critically) certificate-based authentication to Active Directory itself. There are usually only one or a handful of them, often fewer than the domain controller count, but a CA's blast radius rivals a DC's for a different reason: whoever controls the CA's private key, its issuance policy, or its certificate templates can mint a certificate for any identity in the domain, including Domain Admins, and use it to authenticate as that identity (PKINIT/Kerberos certificate-based logon) without ever touching a password or a Kerberos ticket. Misconfigured or vulnerable certificate templates (the "ESC" privilege-escalation paths — enrollee-supplied subject names, weak enrollment permissions, disabled manager approval) turn a single low-privileged domain account into a domain-admin-equivalent one, entirely through the CA. Because of that blast radius, and because a compromised CA is difficult to fully remediate short of revoking and reissuing every certificate it has ever signed, CAs deserve the same "audit fully from day one" posture as domain controllers rather than the baseline/advanced deferral that's reasonable for the general server fleet. The CA also runs its own, non-`auditpol` audit filter (covered under Advanced settings below) and generates a certificate-services-specific event set — the security-log events documented in the event table below, plus a second, larger set of `Microsoft-Windows-CertificationAuthority` diagnostic-channel events that get their own table further down.

## Baseline settings

The baseline tier is the minimum viable audit configuration: enough to catch logons, account/group changes, process creation, and tampering with the audit trail itself, without generating so much volume that a small team can't keep up.

[`settings/subcategories/certificate-authority-baseline.csv`](../settings/subcategories/certificate-authority-baseline.csv) is an `auditpol /backup`-format file enabling these Advanced Audit Policy subcategories (all under the `System` policy target, restorable directly with `auditpol /restore /file:settings/subcategories/certificate-authority-baseline.csv`):

- **Account Logon**: Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations
- **Account Management**: Computer Account Management, Security Group Management, User Account Management
- **Detailed Tracking**: Process Creation
- **Logon/Logoff**: Account Lockout, Logoff, Logon, Special Logon
- **Policy Change**: Audit Policy Change
- **Privilege Use**: Sensitive Privilege Use
- **System**: Security State Change, Security System Extension, System Integrity

This is the same 16-subcategory core used in the workstation and server baselines — identical in content to [`settings/subcategories/workstation-baseline.csv`](../settings/subcategories/workstation-baseline.csv). Nothing about the OS-level logon/account/process/policy-tampering baseline changes because a machine happens to run the CA role; what's specific to this role is layered on separately below (the Advanced settings tier's certificate-services subcategory omission and the CA's own audit filter).

Alongside the `auditpol` subcategories, [`settings/registry-settings.csv`](../settings/registry-settings.csv) has rows with `Role = all` or `Role = certificate-authority` and `Tier = baseline`. Every current row in that file is `Role = all` — the same Administrative Templates values apply here as on workstations, servers, and domain controllers:

- PowerShell Module Logging and Script Block Logging (`EnableModuleLogging`, `ModuleNames = *`, `EnableScriptBlockLogging`)
- Including the command line in process creation events (`ProcessCreationIncludeCmdLine_Enabled`) — without this, event 4688 shows the process image but not its arguments
- Forcing subcategory audit policy to override legacy category-level policy (`SCENoApplyLegacyAuditPolicy`)
- Application, Security, and System event log maximum size (4 GB) and retention (do not overwrite) — the source GPO guide for this role recommends an 8 GB Security log specifically, larger than the 4 GB baseline in this repo's shared registry data; size the Security log up from the baseline value on CAs if local retention matters more than forwarding cadence.

See [`settings/README.md`](../settings/README.md) for exactly how to apply either file (`auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback).

## Advanced settings

Beyond baseline, add [`settings/subcategories/certificate-authority-advanced.csv`](../settings/subcategories/certificate-authority-advanced.csv), which layers on top of every baseline subcategory (it's a superset, not a delta — restoring it alone gives you baseline + advanced in one step; 16 baseline subcategories + 12 advanced = 28 total rows in the file) plus these additional subcategories:

- **Account Management**: Other Account Management Events
- **Detailed Tracking**: DPAPI Activity
- **Object Access**: File System, Handle Manipulation, Registry, Kernel Object, File Share, Detailed File Share
- **Policy Change**: Authentication Policy Change, MPSSVC Rule-Level Policy Change, Other Policy Change Events
- **Logon/Logoff**: Other Logon/Logoff Events

This is the same 12-subcategory advanced layer used in the other three guides. Note what it does *not* include: the `Certification Services` subcategory (Object Access) that the source `Certificate Authority Server Security Event Logging GPO Configuration Guide.md` calls out under "Audit Certification Services: Success and Failure." That subcategory isn't part of this repo's settings CSVs, but it is a real, separate prerequisite from the CA's own audit filter below — Windows will not generate the 4868–4898 certificate-services events unless *both* the `Certification Services` auditpol subcategory is enabled (`auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`) *and* the CA-level audit filter is set. Enable it manually alongside the CSV-driven settings above.

The corresponding `Tier = advanced` row in [`settings/registry-settings.csv`](../settings/registry-settings.csv) for this role enables PowerShell Transcription (`EnableTranscripting`) — optional, and only useful if you also configure an `OutputDirectory` to centralize the transcript files; otherwise they sit locally on each CA.

**CA-specific audit filter (not an `auditpol` or registry setting, so it's documented here rather than in `settings/`).** The Certificate Authority service has its own, separate audit filter that gates whether it emits the 4868–4898 security-log events at all, independent of the OS-level `Certification Services` subcategory above — both gates have to be open. `Certificate Authority Server Security Event Logging GPO Configuration Guide.md`'s "Certificate Services Operations" section lists all seven CA audit categories as `Success and Failure`:

- Start and Stop Certificate Services (bit 1)
- Backup and Restore CA Database (bit 2)
- Issue and Manage Certificate Requests (bit 4)
- Revoke Certificates and Publish CRLs (bit 8)
- Store and Retrieve Archived Keys (bit 16)
- Change CA Security Settings (bit 32)
- Change CA Configuration (bit 64)

Summed, that's an audit filter value of **127** (all seven bits set), applied with:

```
certutil -setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

(a `certsvc` restart is required for the new filter to take effect). The same seven categories can be enabled equivalently through the CA MMC snap-in (`certsrv.msc`) → right-click the CA → **Properties** → **Auditing** tab → check all seven boxes. Treat this filter value itself as a monitored setting: a CA audit filter silently reduced from 127 is functionally the same as clearing the audit policy on any other role, and is exactly what event 4885 (the audit filter for Certificate Services changed) exists to catch — see Role-specific notes below.

## Event table

Every event in [`event-catalog/events.json`](../event-catalog/events.json) whose `applicableRoles` includes `certificate-authority`, sorted by Event ID. See [`event-catalog/full-table.md`](../event-catalog/full-table.md) for the complete cross-role catalog.

| Event ID | Log Source | Description | Criticality | MITRE Technique(s) |
|----------|-----------|-------------|-------------|---------------------|
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
| 4868 | Security | Certificate Manager denied certificate request | High | T1552.004 - Private Keys |
| 4869 | Security | Certificate Services received resubmitted request | High | T1552.004 - Private Keys |
| 4870 | Security | Certificate Services revoked certificate | High | T1552.004 - Private Keys |
| 4871 | Security | Certificate Services received a request to publish CRL | Medium | T1552.004 - Private Keys |
| 4872 | Security | Certificate Services published the CA certificate to AD DS | Medium | T1552.004 - Private Keys |
| 4873 | Security | Certificate request extension changed | High | T1552.004 - Private Keys |
| 4874 | Security | One or more certificate request attributes changed | High | T1552.004 - Private Keys |
| 4875 | Security | Certificate Services received a request to shut down | High | T1562 - Impair Defenses |
| 4876 | Security | Certificate Services backup started | Medium | T1552.004 - Private Keys |
| 4877 | Security | Certificate Services backup completed | Medium | T1552.004 - Private Keys |
| 4878 | Security | Certificate Services restore started | High | T1552.004 - Private Keys |
| 4879 | Security | Certificate Services restore completed | High | T1552.004 - Private Keys |
| 4880 | Security | Certificate Services started | Medium | T1552.004 - Private Keys |
| 4881 | Security | Certificate Services stopped | High | T1562 - Impair Defenses |
| 4882 | Security | Security permissions on CA changed | High | T1222 - File and Directory Permissions Modification |
| 4883 | Security | Certificate Services retrieved an archived key | High | T1552.004 - Private Keys |
| 4884 | Security | Certificate Services imported a certificate into its database | High | T1552.004 - Private Keys |
| 4885 | Security | Audit filter for Certificate Services changed | High | T1562.002 - Disable Windows Event Logging |
| 4886 | Security | Certificate Services received a certificate request | Medium | T1552.004 - Private Keys |
| 4887 | Security | Certificate issued | High | T1552.004 - Private Keys |
| 4888 | Security | Certificate request denied | Medium | T1552.004 - Private Keys |
| 4889 | Security | Certificate Services set the status of a certificate request to pending | Medium | T1552.004 - Private Keys |
| 4890 | Security | Certificate Manager settings changed | High | T1562 - Impair Defenses |
| 4891 | Security | Configuration entry changed in Certificate Services | High | T1562 - Impair Defenses |
| 4892 | Security | Property of Certificate Services changed | High | T1562 - Impair Defenses |
| 4893 | Security | Certificate Services archived a key | High | T1552.004 - Private Keys |
| 4894 | Security | Certificate Services imported and archived a key | High | T1552.004 - Private Keys |
| 4895 | Security | Certificate Services published CA certificate to AD DS | Medium | T1552.004 - Private Keys |
| 4896 | Security | Certificate Services database row deleted | High | T1485 - Data Destruction |
| 4897 | Security | Role separation enabled | High | T1548 - Abuse Elevation Control Mechanism |
| 4898 | Security | Certificate Services loaded a template | Medium | T1552.004 - Private Keys |
| 4946 | Security | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 4947 | Security | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 4948 | Security | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 4950 | Security | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules |
| 5140 | Security | Network share accessed | High | T1021.002 - SMB/Windows Admin Shares |
| 5142 | Security | Network share object added | High | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Security | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |
| 5156 | Security | Windows Filtering Platform allowed connection | Medium | T1047 - Windows Management Instrumentation; T1562.004 - Disable or Modify Firewall Rules |
| 5857 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation |
| 5858 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation |
| 5859 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation |
| 7022 | System | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | System | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7031 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | System | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | System | Service start type changed | High | T1543.003 - Windows Service; T1562 - Impair Defenses |
| 7045 | System | New service installed | High | T1543.003 - Windows Service |

### CertificationAuthority diagnostic events

`Active Directory Certificate Authority Event ID Collection Guide.md` documents a second, larger set of 38 events (IDs 3–40) from the `Microsoft-Windows-CertificationAuthority` diagnostic channel. Those IDs are only unique *within* that channel — they collide with unrelated events from other channels used elsewhere in this guide set (for example, ID 21 is also "RDP Session Logon Succeeded" in the `Terminal-Services-LocalSessionManager/Operational` channel, and ID 8 is also a WMI-Activity error in the workstation guide's event table) — so because [`event-catalog/events.json`](../event-catalog/events.json) keys solely on Event ID with no per-channel field, these 38 events were deliberately excluded from the shared catalog rather than forced into it under a false shared identity. They're kept here instead, as this channel's own table, transcribed directly from the source document:

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 3 | Request failed | Medium | T1552.004 - Private Keys |
| 4 | Request did not contain template name | Medium | T1552.004 - Private Keys |
| 5 | Services could not initialize | High | T1562 - Impair Defenses |
| 6 | Services issued a certificate | Medium | T1552.004 - Private Keys |
| 7 | Services denied request | Medium | T1552.004 - Private Keys |
| 8 | Services request pending | Medium | T1552.004 - Private Keys |
| 9 | Services could not create key container | High | T1562 - Impair Defenses |
| 10 | Services failed to archive private key | High | T1552.004 - Private Keys |
| 11 | Services could not get key storage provider information | High | T1562 - Impair Defenses |
| 12 | Services could not get container | High | T1562 - Impair Defenses |
| 13 | Services template missing | High | T1562 - Impair Defenses |
| 14 | Services could not find request file | Medium | T1562 - Impair Defenses |
| 15 | Services did not start | High | T1562 - Impair Defenses |
| 16 | Services could not read request file | Medium | T1562 - Impair Defenses |
| 17 | Services could not open request file | Medium | T1562 - Impair Defenses |
| 18 | Services policy module error | High | T1562 - Impair Defenses |
| 19 | Services exit module error | High | T1562 - Impair Defenses |
| 20 | Services could not initialize policy module | High | T1562 - Impair Defenses |
| 21 | Services could not initialize exit module | High | T1562 - Impair Defenses |
| 22 | Services invalid certificate template | High | T1562 - Impair Defenses |
| 23 | Services template OID missing | High | T1562 - Impair Defenses |
| 24 | Services template not supported | High | T1562 - Impair Defenses |
| 25 | Services key archival template not found | High | T1562 - Impair Defenses |
| 26 | Services could not find key archival certificate | High | T1562 - Impair Defenses |
| 27 | Services could not archive private key | High | T1552.004 - Private Keys |
| 28 | Services could not create key archival hash | High | T1562 - Impair Defenses |
| 29 | Services could not create key archival certificate | High | T1562 - Impair Defenses |
| 30 | Services could not archive private key | High | T1552.004 - Private Keys |
| 31 | Services could not process request | High | T1562 - Impair Defenses |
| 32 | Services could not sign request | High | T1562 - Impair Defenses |
| 33 | Services could not sign request (error) | High | T1562 - Impair Defenses |
| 34 | Services could not create certificate | High | T1562 - Impair Defenses |
| 35 | Services could not open registry key | High | T1562 - Impair Defenses |
| 36 | Services could not read registry value | High | T1562 - Impair Defenses |
| 37 | Services could not write registry value | High | T1562 - Impair Defenses |
| 38 | Services could not get subject name | High | T1562 - Impair Defenses |
| 39 | Services could not get subject alt name | High | T1562 - Impair Defenses |
| 40 | Services could not get request attributes | High | T1562 - Impair Defenses |

## Role-specific notes

Priorities specific to certificate authorities, condensed from the source guide's "Key Monitoring Scenarios" and operational experience running AD CS (not redundant with what the event tables above already show):

- **Certificate template misconfiguration is the top CA-specific detection priority, and it's mostly invisible to the event log.** The ESC1–ESC8 privilege-escalation paths (enrollee-supplied subject names, weak enrollment ACLs, disabled manager approval, misconfigured `certsrv` web enrollment) let a low-privileged account request and receive a certificate for a high-privileged identity, and the resulting issuance shows up as an entirely ordinary-looking 4886/4887 (request received / certificate issued). Event logging alone doesn't catch a bad template — template auditing has to be paired with a periodic review of `certutil -template` / `Get-CertificateTemplate` output against known-vulnerable patterns; treat 4887 volume and 4898 (template loaded) as a trigger to re-check template ACLs, not as sufficient evidence on their own.
- **Unauthorized or unexpected certificate issuance is the highest-value real-time signal.** 4886 (request received) → 4887 (approved and issued) or 4888/4868 (denied) for identities that shouldn't be requesting certificates at all (a service account, a machine outside its expected OU, a template intended for a different population) is the most direct evidence of certificate-based privilege escalation or persistence in progress — alert on issuance against sensitive templates (domain controller authentication, smart-card logon, code signing) specifically, not just on 4887 in aggregate.
- **CA audit-filter and service tampering deserve the same non-negotiable priority as audit-policy tampering everywhere else, with an extra gate to watch.** 4885 (the CA's own audit filter changed) is this role's equivalent of 4719 (system audit policy changed) — a drop from the recommended value 127 (see Advanced settings above) silently blinds 4868–4898 without touching `auditpol` at all, so it won't show up as a normal audit-policy-change alert on 4719. Pair 4885 with 4875/4881 (CA service shutdown/stop) and 1102/1100 (Security log cleared / logging service stopped) as the CA's core "someone is covering their tracks" cluster.
- **Private key archival and retrieval operations are a direct path to key theft, not just metadata changes.** 4883 (archived key retrieved), 4893 (key archived), and 4894 (key imported and archived) touch the actual private key material for archived certificates; any retrieval (4883) outside a documented key-recovery procedure is high-priority, and the diagnostic-channel failures around archival (events 9, 10, 25–30 in the table above) are worth correlating against them — repeated archival failures immediately preceding a successful 4883 can indicate an attacker iterating toward a working extraction.
- **Backup, restore, and database operations are rare enough that any occurrence outside a maintenance window warrants investigation.** 4876/4877 (backup started/completed) and 4878/4879 (restore started/completed) should only ever coincide with a planned backup schedule; a restore (4878) outside one is a strong indicator of an attacker rolling the CA database back to reintroduce a revoked certificate or hide evidence, and 4896 (database row marked deleted) deserves the same scrutiny as 4660 (object deleted) elsewhere in this guide.
- **Permission and configuration changes on the CA itself are a smaller blast radius than a template change but still high-signal.** 4882 (security permissions on CA changed), 4890 (Certificate Manager settings changed), 4891/4892 (configuration entry/property changed), and 4897 (role separation enabled/disabled) cover who can manage the CA and how it's configured — treat unplanned changes here with the same urgency as 4907/4912 in the server-baseline guide, since loosening CA permissions is a direct route to the template and issuance abuse above.
- **The diagnostic-channel events (table above) are the CA's own health and tamper telemetry, complementary to the security log rather than a duplicate of it.** Most of the 38 events are policy-module, exit-module, and registry-access failures (events 9–40) that indicate either genuine operational problems or an attacker probing/breaking the CA's request-processing pipeline; a cluster of these immediately before or after a 4887 (certificate issued) is worth treating as suspicious rather than routine noise, especially registry-access failures (35–37) or policy/exit-module errors (18–21), which point at tampering with the CA's own extension modules.
- **Audit-log tampering detection is not optional at any tier, and here it spans two separate logs.** 1102 (audit log cleared), 1100 (logging service shut down), and 4719 (audit policy changed) apply to the Security log exactly as they do on every other role in this guide set — forward them off-box and alert immediately. On a CA, extend that same non-negotiable treatment to 4885, since it's the CA-specific mechanism for achieving the identical outcome (loss of certificate-services visibility) without ever touching the OS-level audit policy that 4719 monitors.
