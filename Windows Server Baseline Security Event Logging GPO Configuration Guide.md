# Windows Server Baseline Security Event Logging GPO Configuration Guide

## Advanced Audit Policy Configuration
Navigate to: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration

### Account Logon
- Audit Credential Validation: Success and Failure
- Audit Kerberos Authentication Service: Success and Failure
- Audit Kerberos Service Ticket Operations: Success and Failure
- Audit Other Account Logon Events: Success and Failure

### Account Management
- Audit Application Group Management: Success and Failure
- Audit Computer Account Management: Success and Failure
- Audit Distribution Group Management: Success and Failure
- Audit Other Account Management Events: Success and Failure
- Audit Security Group Management: Success and Failure
- Audit User Account Management: Success and Failure

### Detailed Tracking
- Audit DPAPI Activity: Success and Failure
- Audit PNP Activity: Success and Failure
- Audit Process Creation: Success
  - Note: Also enable command line logging under Administrative Templates
- Audit Process Termination: Success
- Audit RPC Events: Success and Failure
- Audit Token Right Adjusted Events: Success and Failure

### Logon/Logoff
- Audit Account Lockout: Success and Failure
- Audit Group Membership: Success
- Audit Logoff: Success
- Audit Logon: Success and Failure
- Audit Network Policy Server: Success and Failure
- Audit Other Logon/Logoff Events: Success and Failure
- Audit Special Logon: Success and Failure
- Audit User/Device Claims: Success and Failure

### Object Access
- Audit Application Generated: Success and Failure
- Audit Certification Services: Success and Failure
- Audit Detailed File Share: Success and Failure
- Audit File Share: Success and Failure
- Audit File System: Success and Failure
- Audit Filtering Platform Connection: Success and Failure
- Audit Filtering Platform Packet Drop: Success and Failure
- Audit Handle Manipulation: Success and Failure
- Audit Kernel Object: Success and Failure
- Audit Other Object Access Events: Success and Failure
- Audit Registry: Success and Failure
- Audit Removable Storage: Success and Failure
- Audit SAM: Success and Failure
- Audit Central Policy Staging: Success and Failure

### Policy Change
- Audit Audit Policy Change: Success and Failure
- Audit Authentication Policy Change: Success and Failure
- Audit Authorization Policy Change: Success and Failure
- Audit Filtering Platform Policy Change: Success and Failure
- Audit MPSSVC Rule-Level Policy Change: Success and Failure
- Audit Other Policy Change Events: Success and Failure

### Privilege Use
- Audit Non Sensitive Privilege Use: Failure
- Audit Sensitive Privilege Use: Success and Failure
- Audit Other Privilege Use Events: Success and Failure

### System
- Audit IPsec Driver: Success and Failure
- Audit Other System Events: Success and Failure
- Audit Security State Change: Success and Failure
- Audit Security System Extension: Success and Failure
- Audit System Integrity: Success and Failure

## Administrative Templates Configuration
Navigate to: Computer Configuration → Administrative Templates

### Windows PowerShell
- Turn on Module Logging
  - Enable
  - Module Names: *
- Turn on PowerShell Script Block Logging
  - Enable
  - Log script block invocation start/stop events: Enabled
- Turn on PowerShell Transcription
  - Enable
  - Include invocation headers: Enabled
  - Specify transcript output directory

### System → Audit Process Creation
- Include command line in process creation events: Enable

### Microsoft Windows Security Auditing
- Force audit policy subcategory settings to override audit policy category settings: Enable

### Windows Components → Event Log Service → Security
- Maximum Log Size (KB): 8388608 (8GB)
- Retain old events: Enabled
- Log Access: Enabled
- Backup log automatically when full: Disabled
- Control Event Log behavior when the log file reaches its maximum size: Disabled

### Windows Components → Event Log Service → System
- Maximum Log Size (KB): 4194304 (4GB)
- Retain old events: Enabled
- Log Access: Enabled
- Backup log automatically when full: Disabled

### Windows Components → Event Log Service → Application
- Maximum Log Size (KB): 4194304 (4GB)
- Retain old events: Enabled
- Log Access: Enabled
- Backup log automatically when full: Disabled

### Windows Components → Windows Remote Management (WinRM) → WinRM Client
- Allow Basic authentication: Disabled
- Allow CredSSP authentication: Disabled
- Allow unencrypted traffic: Disabled
- Disallow Digest authentication: Enabled
- Disallow Kerberos authentication: Disabled
- Disallow Negotiate authentication: Disabled
- Trusted Hosts: Specify allowed hosts

### Windows Components → Windows Remote Management (WinRM) → WinRM Service
- Allow Basic authentication: Disabled
- Allow CredSSP authentication: Disabled
- Allow remote server management through WinRM: 
  - Enable
  - IPv4 filter: * (or specific IPs)
- Allow unencrypted traffic: Disabled
- Disallow Kerberos authentication: Disabled
- Disallow Negotiate authentication: Disabled
- Specify channel binding token hardening level: Strict
- Turn on Compatibility HTTP Listener: Disabled
- Turn on Compatibility HTTPS Listener: Disabled

### Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security
- Always prompt for password upon connection: Enabled
- Require secure RPC communication: Enabled
- Require user authentication for remote connections by using Network Level Authentication: Enabled
- Set client connection encryption level: High Level

### Windows Firewall
- Windows Firewall: Use this profile: Enable
- Windows Firewall: Display notifications: Enable
- Windows Firewall Logging:
  - Log dropped packets: Enable
  - Log successful connections: Enable
  - Size limit (KB): 32768

### Windows Components → Windows Defender Antivirus → Reporting
- Configure enhanced notifications: Enabled
- Configure local setting override for reporting to Microsoft MAPS: Disabled
- Turn on e-mail notification: Enabled (if needed)

## Important Notes:
1. After applying these settings, run gpupdate /force on target systems
2. Monitor event log sizes as these settings will generate significant logging
3. Consider implementing log forwarding or centralized logging
4. Some settings may need tuning based on environment size and activity
5. Ensure sufficient disk space for increased logging
6. Consider implementing log rotation or archival policies

## Best Practices:
1. Test GPO settings in a controlled environment first
2. Document any customizations made for your environment
3. Regularly review and update audit policies
4. Monitor log sizes and adjust as needed
5. Implement log collection and analysis solution
6. Create alerts for critical security events
7. Regular backup of event logs
8. Regular review of audit policy effectiveness

## Service-Specific Considerations:
1. Adjust settings based on server role (file server, application server, etc.)
2. Consider additional role-specific audit requirements
3. Balance security requirements with performance impact
4. Document any deviations from baseline
5. Review and adjust WinRM settings based on remote management needs
6. Configure appropriate firewall rules for server role