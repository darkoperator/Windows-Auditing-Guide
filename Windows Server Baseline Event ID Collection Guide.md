# Windows Server Baseline Event ID Collection Guide

## Security Log Events - Authentication & Account Usage

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4624 | Successful account logon | High | T1078 - Valid Accounts |
| 4625 | Failed account logon | High | T1110 - Brute Force |
| 4634 | Account logoff | Medium | T1078 - Valid Accounts |
| 4647 | User initiated logoff | Low | T1078 - Valid Accounts |
| 4648 | Logon using explicit credentials | High | T1078 - Valid Accounts |
| 4672 | Special privileges assigned to new logon | High | T1078.003 - Local Accounts |
| 4776 | Credential validation | High | T1110 - Brute Force |
| 4778 | Session reconnected to window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4779 | Session disconnected from window station | Medium | T1021.001 - Remote Desktop Protocol |
| 4740 | Account locked out | High | T1110 - Brute Force |
| 4767 | Account unlocked | Medium | T1078 - Valid Accounts |

## Security Log Events - System Access Control

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4720 | User account created | High | T1136 - Create Account |
| 4722 | User account enabled | High | T1078 - Valid Accounts |
| 4723 | Password change attempt | High | T1098 - Account Manipulation |
| 4724 | Password reset attempt | High | T1098 - Account Manipulation |
| 4725 | User account disabled | High | T1098 - Account Manipulation |
| 4726 | User account deleted | High | T1531 - Account Access Removal |
| 4738 | User account changed | High | T1098 - Account Manipulation |
| 4732 | Member added to security-enabled local group | High | T1098 - Account Manipulation |
| 4733 | Member removed from security-enabled local group | High | T1098 - Account Manipulation |
| 4728 | Member added to security-enabled global group | High | T1098 - Account Manipulation |
| 4729 | Member removed from security-enabled global group | High | T1098 - Account Manipulation |

## Security Log Events - Process & Program Activity

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4688 | Process creation | High | T1059 - Command and Scripting Interpreter |
| 4689 | Process termination | Medium | T1059 - Command and Scripting Interpreter |
| 4696 | Primary token assigned to process | High | T1134 - Access Token Manipulation |
| 4697 | Service installation | High | T1543.003 - Windows Service |
| 4698 | Scheduled task created | High | T1053.005 - Scheduled Task |
| 4699 | Scheduled task deleted | High | T1053.005 - Scheduled Task |
| 4700 | Scheduled task enabled | Medium | T1053.005 - Scheduled Task |
| 4701 | Scheduled task disabled | Medium | T1053.005 - Scheduled Task |
| 4702 | Scheduled task updated | High | T1053.005 - Scheduled Task |

## Security Log Events - Object Access & Modifications

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4656 | Handle to an object was requested | High | T1003.001 - LSASS Memory |
| 4657 | Registry value modified | High | T1112 - Modify Registry |
| 4660 | Object deleted | High | T1485 - Data Destruction |
| 4663 | Object access attempt (useful for LSASS) | High | T1003.001 - LSASS Memory |
| 4670 | Permissions on an object changed | High | T1222 - File and Directory Permissions Modification |
| 5140 | Network share was accessed | High | T1021.002 - SMB/Windows Admin Shares |
| 5142 | Network share object added | High | T1021.002 - SMB/Windows Admin Shares |
| 5143 | Network share object modified | High | T1021.002 - SMB/Windows Admin Shares |
| 5144 | Network share object deleted | High | T1021.002 - SMB/Windows Admin Shares |
| 5145 | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares |

## Security Log Events - Policy Changes

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4719 | System audit policy changed | High | T1562.002 - Disable Windows Event Logging |
| 4905 | Security event source unregistered | High | T1562.002 - Disable Windows Event Logging |
| 4907 | Auditing settings changed on object | High | T1562.002 - Disable Windows Event Logging |
| 4912 | Per-user audit policy changed | High | T1562.002 - Disable Windows Event Logging |
| 4946 | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 4947 | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 4948 | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 4950 | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules |

## PowerShell Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4103 | Module logging | High | T1059.001 - PowerShell |
| 4104 | Script block logging | High | T1059.001 - PowerShell |
| 403 | Engine lifecycle (Windows PowerShell) | High | T1059.001 - PowerShell |

## System Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 1100 | Event logging service shut down | High | T1562.002 - Disable Windows Event Logging |
| 1102 | Audit log cleared | High | T1070.001 - Clear Windows Event Logs |
| 1104 | Security log is now full | High | T1562.002 - Disable Windows Event Logging |
| 7022 | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7026 | Service crashed | Medium | T1543.003 - Windows Service |
| 7031 | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | Service start type changed | High | T1543.003 - Windows Service |
| 7045 | New service installed | High | T1543.003 - Windows Service |

## RDP/RDS Events 

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 131 | RDP Connection Attempt | High | T1021.001 - Remote Desktop Protocol |
| 140 | RDP Connection Succeeded | High | T1021.001 - Remote Desktop Protocol |
| 21 | RDP Session Logon Succeeded | High | T1021.001 - Remote Desktop Protocol |
| 22 | RDP Shell Start Notification | Medium | T1021.001 - Remote Desktop Protocol |
| 23 | RDP Session Logoff | Medium | T1021.001 - Remote Desktop Protocol |
| 24 | RDP Session Disconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 25 | RDP Session Reconnected | Medium | T1021.001 - Remote Desktop Protocol |
| 39 | RDP Session Disconnected by Admin | High | T1021.001 - Remote Desktop Protocol |
| 40 | RDP Session Disconnected by Reason Code | Medium | T1021.001 - Remote Desktop Protocol |
| 1149 | User Authentication Succeeded | High | T1021.001 - Remote Desktop Protocol |

## WMI Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 5857 | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation |
| 5858 | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation |
| 5859 | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation |
| 5860 | WMI Activity - Consumer Error | High | T1047 - Windows Management Instrumentation |
| 5861 | WMI Activity - Consumer Warning | Medium | T1047 - Windows Management Instrumentation |

## Notes:
- Criticality levels:
  - High: Critical security events that should always be monitored
  - Medium: Important events that provide valuable context
  - Low: Events that are useful for forensics but may not require immediate attention

## Key Monitoring Scenarios:
1. Unauthorized access attempts
2. Privileged account usage
3. Service installation and modifications
4. Scheduled task creation/modification
5. Security policy changes
6. Remote access (RDP/WMI)
7. PowerShell and script execution
8. Object/file access
9. Registry modifications
10. Network share activity

## Required Audit Policies:
1. Account Logon Events
2. Account Management
3. Detailed File Share
4. Logon Events
5. Object Access
6. Policy Change
7. Privilege Use
8. Process Tracking
9. System Events

## Important Log Sources:
1. Security
2. System
3. Application
4. PowerShell/Operational
5. Microsoft-Windows-PowerShell/Operational
6. Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
7. Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
8. Microsoft-Windows-WMI-Activity/Operational