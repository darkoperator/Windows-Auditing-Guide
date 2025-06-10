# Domain Controller Event ID Collection Guide

## Security Log Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4624 | Successful account logon | High | T1078 - Valid Accounts |
| 4625 | Failed account logon | High | T1110 - Brute Force |
| 4634 | Account logoff | Medium | T1078 - Valid Accounts |
| 4648 | Explicit credential logon | High | T1078 - Valid Accounts, T1550.002 - Pass the Hash |
| 4663 | An attempt was made to access an object (useful for LSASS access) | High | T1003 - OS Credential Dumping, T1003.001 - LSASS Memory |
| 4672 | Special privileges assigned to new logon | High | T1078 - Valid Accounts, T1548 - Abuse Elevation Control Mechanism |
| 4688 | Process creation (with command line logging) | High | T1059 - Command and Scripting Interpreter |
| 4698 | Scheduled task created | High | T1053.005 - Scheduled Task |
| 4699 | Scheduled task deleted | High | T1053.005 - Scheduled Task |
| 4700 | Scheduled task enabled | Medium | T1053.005 - Scheduled Task |
| 4701 | Scheduled task disabled | Medium | T1053.005 - Scheduled Task |
| 4702 | Scheduled task updated | High | T1053.005 - Scheduled Task |
| 4719 | System audit policy was changed | High | T1562.002 - Disable Windows Event Logging |
| 4720 | User account created | High | T1136 - Create Account |
| 4722 | User account enabled | Medium | T1078 - Valid Accounts |
| 4723 | Password change attempt | Medium | T1098 - Account Manipulation |
| 4724 | Password reset attempt | High | T1098 - Account Manipulation |
| 4725 | User account disabled | Medium | T1098 - Account Manipulation |
| 4726 | User account deleted | High | T1531 - Account Access Removal |
| 4728 | Member added to security-enabled global group | Medium | T1098 - Account Manipulation |
| 4729 | Member removed from security-enabled global group | Medium | T1098 - Account Manipulation |
| 4732 | Member added to security-enabled local group | Medium | T1098 - Account Manipulation |
| 4733 | Member removed from security-enabled local group | Medium | T1098 - Account Manipulation |
| 4738 | User account changed | Medium | T1098 - Account Manipulation |
| 4740 | User account locked out | High | T1110 - Brute Force |
| 4756 | Member added to security-enabled universal group | Medium | T1098 - Account Manipulation |
| 4757 | Member removed from security-enabled universal group | Medium | T1098 - Account Manipulation |
| 4767 | User account unlocked | Medium | T1098 - Account Manipulation |
| 4768 | Kerberos authentication ticket (TGT) requested | High | T1558.003 - Kerberoasting |
| 4769 | Kerberos service ticket requested | High | T1558.003 - Kerberoasting |
| 4771 | Kerberos pre-authentication failed | High | T1110 - Brute Force |
| 4776 | Credential validation | High | T1110 - Brute Force |
| 4794 | Directory Services Restore Mode admin password set | High | T1098 - Account Manipulation |
| 4897 | Role separation enabled | High | T1548 - Abuse Elevation Control Mechanism |
| 4964 | Special groups assigned to new logon | High | T1078 - Valid Accounts |

## System Log Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 1102 | Audit log cleared | High | T1070.001 - Clear Windows Event Logs |
| 6005 | Event log service started | Medium | T1562 - Impair Defenses |
| 6006 | Event log service stopped | Medium | T1562 - Impair Defenses |
| 7040 | Service start type changed | High | T1562 - Impair Defenses |
| 7045 | New service installed | High | T1543.003 - Windows Service |

## Microsoft-Windows-PowerShell/Operational

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4103 | Module logging | High | T1059.001 - PowerShell |
| 4104 | Script block logging | High | T1059.001 - PowerShell |

## Windows PowerShell Log

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 403 | PowerShell engine started/stopped | High | T1059.001 - PowerShell |

## Microsoft-Windows-Terminal-Services-LocalSessionManager/Operational

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 21 | Remote Desktop login succeeded | High | T1021.001 - Remote Desktop Protocol |
| 22 | Remote Desktop shell start | Medium | T1021.001 - Remote Desktop Protocol |
| 23 | Remote Desktop logoff | Medium | T1021.001 - Remote Desktop Protocol |
| 24 | Remote Desktop session disconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 25 | Remote Desktop session reconnected | Medium | T1021.001 - Remote Desktop Protocol |

## Directory Service Log Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4662 | Operation performed on Active Directory object | High | T1087.002 - Domain Account Discovery |
| 5136 | Directory Service object modified | High | T1484 - Domain Policy Modification |
| 5137 | Directory Service object created | High | T1484 - Domain Policy Modification |
| 5138 | Directory Service object undeleted | High | T1484 - Domain Policy Modification |
| 5139 | Directory Service object moved | High | T1484 - Domain Policy Modification |
| 5141 | Directory Service object deleted | High | T1484 - Domain Policy Modification |

## File System and Registry Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4656 | A handle to an object was requested | High | T1003.001 - LSASS Memory |
| 4657 | Registry value modified | High | T1112 - Modify Registry |
| 4658 | Handle to object closed | Medium | T1003.001 - LSASS Memory |
| 4660 | Object deleted | High | T1485 - Data Destruction |
| 4663 | Object access attempt | High | T1003.001 - LSASS Memory |
| 4670 | Object permissions changed | High | T1222 - File and Directory Permissions Modification |
| 5140 | Network share accessed | Medium | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |

## Windows Firewall Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4946 | Rule added to Windows Firewall exception list | High | T1562.004 - Disable/Modify Firewall |
| 4947 | Rule modified in Windows Firewall exception list | High | T1562.004 - Disable/Modify Firewall |
| 4948 | Rule deleted from Windows Firewall exception list | High | T1562.004 - Disable/Modify Firewall |
| 4950 | Windows Firewall settings changed | High | T1562.004 - Disable/Modify Firewall |
| 4954 | Group policy settings for Windows Firewall changed | High | T1562.004 - Disable/Modify Firewall |
| 4956 | Windows Firewall active profile changed | Medium | T1562.004 - Disable/Modify Firewall |
| 5024 | Windows Firewall service started | Medium | T1562.004 - Disable/Modify Firewall |
| 5025 | Windows Firewall service stopped | High | T1562.004 - Disable/Modify Firewall |
| 5031 | Application blocked from accepting incoming connections | High | T1562.004 - Disable/Modify Firewall |
| 5152 | Network packet blocked by Windows Filtering Platform | Medium | T1562.004 - Disable/Modify Firewall |
| 5153 | A more restrictive Windows Filtering Platform filter blocked a packet | Medium | T1562.004 - Disable/Modify Firewall |
| 5155 | Windows Filtering Platform blocked an application from listening on a port | High | T1562.004 - Disable/Modify Firewall |
| 5157 | Windows Filtering Platform blocked a connection | Medium | T1562.004 - Disable/Modify Firewall |

## Notes:
- Criticality levels:
  - High: Critical security events that should always be monitored
  - Medium: Important events that provide valuable context
- MITRE ATT&CK Technique IDs help map events to known adversary tactics and techniques
- All events should be collected with their full details including Success/Failure status where applicable
- Command line logging should be enabled for Process Creation events (4688)
- PowerShell logging should include both Module and Script Block logging
- Consider storage requirements when enabling comprehensive logging
- For object access events (4663), consider filtering specifically for LSASS access to reduce noise
- Registry monitoring can generate significant volume - consider focusing on sensitive registry keys
- Firewall events should be tuned based on your environment's baseline