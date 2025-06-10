# Master Windows Event ID Reference Table

| Event ID | Log Name | Description | Criticality | MITRE Technique | Applicable To |
|----------|----------|-------------|-------------|-----------------|---------------|
| 403 | Windows PowerShell | PowerShell engine lifecycle | High | T1059.001 - PowerShell | All |
| 1000 | Application | Application crash | Medium | T1546 - Event Triggered Execution | W,S |
| 1002 | Application | Application hang | Medium | T1546 - Event Triggered Execution | W,S |
| 1006 | Microsoft-Windows-Windows Defender/Operational | Malware detected | High | T1047 - Windows Management Instrumentation | W,S |
| 1100 | Security | Event logging service shut down | High | T1562.002 - Disable Windows Event Logging | All |
| 1102 | Security | Audit log cleared | High | T1070.001 - Clear Windows Event Logs | All |
| 1104 | Security | Security log full | High | T1562.002 - Disable Windows Event Logging | All |
| 1149 | Terminal-Services-RemoteConnectionManager/Operational | User authentication succeeded | High | T1021.001 - Remote Desktop Protocol | All |
| 4103 | Microsoft-Windows-PowerShell/Operational | Module logging | High | T1059.001 - PowerShell | All |
| 4104 | Microsoft-Windows-PowerShell/Operational | Script block logging | High | T1059.001 - PowerShell | All |
| 4624 | Security | Successful account logon | High | T1078 - Valid Accounts | All |
| 4625 | Security | Failed account logon | High | T1110 - Brute Force | All |
| 4634 | Security | Account logoff | Medium | T1078 - Valid Accounts | All |
| 4647 | Security | User initiated logoff | Low | T1078 - Valid Accounts | All |
| 4648 | Security | Logon with explicit credentials | High | T1078 - Valid Accounts | All |
| 4656 | Security | Handle to an object requested | High | T1003.001 - LSASS Memory | All |
| 4657 | Security | Registry value modified | High | T1112 - Modify Registry | All |
| 4658 | Security | Handle to object closed | Medium | T1003.001 - LSASS Memory | All |
| 4660 | Security | Object deleted | High | T1485 - Data Destruction | All |
| 4663 | Security | Object access attempt | High | T1003.001 - LSASS Memory | All |
| 4670 | Security | Permissions on object changed | High | T1222 - File and Directory Permissions Modification | All |
| 4672 | Security | Special privileges assigned to new logon | High | T1078.003 - Local Accounts | All |
| 4688 | Security | Process creation | High | T1059 - Command and Scripting Interpreter | All |
| 4689 | Security | Process termination | Medium | T1059 - Command and Scripting Interpreter | All |
| 4696 | Security | Primary token assigned to process | High | T1134 - Access Token Manipulation | All |
| 4697 | Security | Service installation | High | T1543.003 - Windows Service | All |
| 4698 | Security | Scheduled task created | High | T1053.005 - Scheduled Task | All |
| 4699 | Security | Scheduled task deleted | High | T1053.005 - Scheduled Task | All |
| 4700 | Security | Scheduled task enabled | Medium | T1053.005 - Scheduled Task | All |
| 4701 | Security | Scheduled task disabled | Medium | T1053.005 - Scheduled Task | All |
| 4702 | Security | Scheduled task updated | High | T1053.005 - Scheduled Task | All |
| 4719 | Security | System audit policy changed | High | T1562.002 - Disable Windows Event Logging | All |
| 4720 | Security | User account created | High | T1136 - Create Account | All |
| 4722 | Security | User account enabled | High | T1078 - Valid Accounts | All |
| 4723 | Security | Password change attempt | High | T1098 - Account Manipulation | All |
| 4724 | Security | Password reset attempt | High | T1098 - Account Manipulation | All |
| 4725 | Security | User account disabled | High | T1098 - Account Manipulation | All |
| 4726 | Security | User account deleted | High | T1531 - Account Access Removal | All |
| 4728 | Security | Member added to security-enabled global group | High | T1098 - Account Manipulation | All |
| 4729 | Security | Member removed from security-enabled global group | High | T1098 - Account Manipulation | All |
| 4732 | Security | Member added to security-enabled local group | High | T1098 - Account Manipulation | All |
| 4733 | Security | Member removed from security-enabled local group | High | T1098 - Account Manipulation | All |
| 4738 | Security | User account changed | High | T1098 - Account Manipulation | All |
| 4740 | Security | User account locked out | High | T1110 - Brute Force | All |
| 4767 | Security | User account unlocked | Medium | T1078 - Valid Accounts | All |
| 4768 | Security | Kerberos TGT requested | High | T1558.003 - Kerberoasting | S,DC |
| 4769 | Security | Kerberos service ticket requested | High | T1558.003 - Kerberoasting | S,DC |
| 4771 | Security | Kerberos pre-authentication failed | High | T1110 - Brute Force | S,DC |
| 4776 | Security | Credential validation | High | T1110 - Brute Force | All |
| 4778 | Security | Session reconnected to window station | Medium | T1021.001 - Remote Desktop Protocol | All |
| 4779 | Security | Session disconnected from window station | Medium | T1021.001 - Remote Desktop Protocol | All |
| 4868 | Security | Certificate Manager denied certificate request | High | T1552.004 - Private Keys | CA |
| 4869 | Security | Certificate Services received resubmitted request | High | T1552.004 - Private Keys | CA |
| 4870 | Security | Certificate Services revoked certificate | High | T1552.004 - Private Keys | CA |
| 4882 | Security | Security permissions on CA changed | High | T1222 - File and Directory Permissions Modification | CA |
| 4885 | Security | Audit filter for Certificate Services changed | High | T1562.002 - Disable Windows Event Logging | CA |
| 4887 | Security | Certificate issued | High | T1552.004 - Private Keys | CA |
| 4888 | Security | Certificate request denied | Medium | T1552.004 - Private Keys | CA |
| 4896 | Security | Certificate Services database row deleted | High | T1485 - Data Destruction | CA |
| 4897 | Security | Role separation enabled | High | T1548 - Abuse Elevation Control Mechanism | CA |
| 4946 | Security | Firewall rule added | High | T1562.004 - Disable or Modify Firewall Rules | All |
| 4947 | Security | Firewall rule modified | High | T1562.004 - Disable or Modify Firewall Rules | All |
| 4948 | Security | Firewall rule deleted | High | T1562.004 - Disable or Modify Firewall Rules | All |
| 4950 | Security | Windows Firewall settings changed | High | T1562.004 - Disable or Modify Firewall Rules | All |
| 5140 | Security | Network share accessed | High | T1021.002 - SMB/Windows Admin Shares | All |
| 5142 | Security | Network share object added | High | T1021.002 - SMB/Windows Admin Shares | All |
| 5145 | Security | Network share object checked | Medium | T1021.002 - SMB/Windows Admin Shares | All |
| 5156 | Security | Windows Filtering Platform allowed connection | Medium | T1562.004 - Disable or Modify Firewall Rules | All |
| 5857 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Started | High | T1047 - Windows Management Instrumentation | All |
| 5858 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Error | High | T1047 - Windows Management Instrumentation | All |
| 5859 | Microsoft-Windows-WMI-Activity/Operational | WMI Activity - Provider Disabled | High | T1047 - Windows Management Instrumentation | All |
| 6416 | Security | A new external device was recognized | High | T1200 - Hardware Additions | W,S |
| 7022 | System | Service hung on starting | Medium | T1543.003 - Windows Service | All |
| 7023 | System | Service terminated with error | Medium | T1543.003 - Windows Service | All |
| 7024 | System | Service terminated with error | Medium | T1543.003 - Windows Service | All |
| 7031 | System | Service crashed | Medium | T1543.003 - Windows Service | All |
| 7034 | System | Service crashed | Medium | T1543.003 - Windows Service | All |
| 7040 | System | Service start type changed | High | T1543.003 - Windows Service | All |
| 7045 | System | New service installed | High | T1543.003 - Windows Service | All |

Legend for Applicable To column:
- All: All Windows systems
- W: Workstations
- S: Servers
- DC: Domain Controllers
- CA: Certificate Authority Servers

## Key Points:
1. This table includes the most security-relevant events for Windows systems
2. Criticality is marked as:
   - High: Critical security events requiring immediate attention
   - Medium: Important events that should be reviewed regularly
   - Low: Informational events useful for forensics
3. MITRE ATT&CK techniques help map events to known attack patterns
4. Different systems may require different monitoring based on their role

## Monitoring Recommendations:
1. Focus first on High criticality events
2. Implement centralized logging
3. Create alerts for critical events
4. Tune monitoring based on system role
5. Regularly review and update monitoring
6. Maintain sufficient log storage
7. Implement log rotation policies
8. Regular backup of event logs