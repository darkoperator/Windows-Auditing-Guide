# Windows Workstation Event ID Collection Guide

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
| 4800 | Workstation locked | Low | T1078 - Valid Accounts |
| 4801 | Workstation unlocked | Low | T1078 - Valid Accounts |
| 4802 | Screen saver invoked | Low | T1078 - Valid Accounts |
| 4803 | Screen saver dismissed | Low | T1078 - Valid Accounts |

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
| 4658 | Handle to object closed | Medium | T1003.001 - LSASS Memory |
| 4660 | Object deleted | High | T1485 - Data Destruction |
| 4663 | Object access attempt (useful for LSASS) | High | T1003.001 - LSASS Memory |
| 4670 | Permissions on an object changed | High | T1222 - File and Directory Permissions Modification |

## PowerShell Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4103 | Module logging | High | T1059.001 - PowerShell |
| 4104 | Script block logging | High | T1059.001 - PowerShell |
| 403 | Engine lifecycle (Windows PowerShell) | High | T1059.001 - PowerShell |

## Windows Defender Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 1006 | Malware detection | High | T1047 - Windows Management Instrumentation |
| 1007 | Malware remediation | High | T1047 - Windows Management Instrumentation |
| 1008 | Malware failed remediation | High | T1047 - Windows Management Instrumentation |
| 1015 | Suspicious behavior detection | High | T1047 - Windows Management Instrumentation |
| 1116 | Detection source | High | T1047 - Windows Management Instrumentation |
| 1117 | AV component started | Medium | T1562.001 - Disable or Modify Tools |
| 1118 | AV component stopped | High | T1562.001 - Disable or Modify Tools |
| 5001 | Real-time protection disabled | High | T1562.001 - Disable or Modify Tools |
| 5004 | Real-time protection configuration changed | High | T1562.001 - Disable or Modify Tools |
| 5007 | Antimalware platform configuration changed | High | T1562.001 - Disable or Modify Tools |
| 5010 | Scanning disabled by tamper protection | High | T1562.001 - Disable or Modify Tools |

## System Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 7022 | Service hung on starting | Medium | T1543.003 - Windows Service |
| 7023 | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7024 | Service terminated with error | Medium | T1543.003 - Windows Service |
| 7026 | Service crashed | Medium | T1543.003 - Windows Service |
| 7031 | Service crashed | Medium | T1543.003 - Windows Service |
| 7034 | Service crashed | Medium | T1543.003 - Windows Service |
| 7040 | Service start type changed | High | T1543.003 - Windows Service |
| 7045 | New service installed | High | T1543.003 - Windows Service |

## Application Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 1000 | Application crash | Medium | T1546 - Event Triggered Execution |
| 1002 | Application hang | Medium | T1546 - Event Triggered Execution |
| 11707 | Install completed successfully | Medium | T1204 - User Execution |
| 11708 | Install failed | Medium | T1204 - User Execution |
| 11724 | Application removal | Medium | T1204 - User Execution |

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
| 5156 | WMI Filter Application | Medium | T1047 - Windows Management Instrumentation |
| 8 | Error accessing object path | High | T1047 - Windows Management Instrumentation |
| 11 | Error starting WMI service | High | T1047 - Windows Management Instrumentation |
| 19 | WMI subscription error | High | T1047 - Windows Management Instrumentation |
| 20 | WMI subscription error | High | T1047 - Windows Management Instrumentation |

## Windows Firewall Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 2003 | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules |
| 2004 | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules |
| 2005 | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules |
| 2006 | Firewall rule group added | High | T1562.004 - Disable or Modify Firewall Rules |
| 2033 | Firewall driver started | Medium | T1562.004 - Disable or Modify Firewall Rules |
| 2034 | Firewall driver stopped | High | T1562.004 - Disable or Modify Firewall Rules |

## External Device Events (USB/Hardware)

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 6416 | A new external device was recognized | High | T1200 - Hardware Additions |
| 6419 | Device installation request | Medium | T1200 - Hardware Additions |
| 6420 | Device disabled | Medium | T1200 - Hardware Additions |
| 6421 | Device installation allowed | Medium | T1200 - Hardware Additions |
| 6422 | Device install enabled | Medium | T1200 - Hardware Additions |
| 6423 | Installation forbidden by policy | Medium | T1200 - Hardware Additions |
| 6424 | Device installation allowed | Medium | T1200 - Hardware Additions |

## Notes:
- Criticality levels:
  - High: Critical security events that should always be monitored
  - Medium: Important events that provide valuable context
  - Low: Events that are useful for forensics but may not require immediate attention

## Key Monitoring Scenarios:
1. Unauthorized access attempts
2. PowerShell and script execution
3. Service installation and modifications
4. Scheduled task creation/modification
5. USB device usage
6. Antivirus/security tool tampering
7. Registry modifications
8. Firewall changes
9. Credential abuse
10. LSASS access attempts

## Recommended Additional Monitoring:
1. Command line logging for process creation (4688)
2. PowerShell script block logging
3. PowerShell module logging
4. USB device auditing
5. Windows Defender detections
6. Service installation and modifications
7. Registry modifications in sensitive keys
8. Firewall rule changes
9. Application installations and crashes
10. RDP session activity