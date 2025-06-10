# Group Policy Audit Settings Configuration Guide

## Advanced Audit Policy Configuration
Navigate to: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration

### Account Logon
- Audit Credential Validation: Success and Failure
- Audit Kerberos Authentication Service: Success and Failure
- Audit Kerberos Service Ticket Operations: Success and Failure

### Account Management
- Audit Computer Account Management: Success and Failure
- Audit Other Account Management Events: Success and Failure
- Audit Security Group Management: Success and Failure
- Audit User Account Management: Success and Failure

### Detailed Tracking
- Audit DPAPI Activity: Success and Failure
- Audit Process Creation: Success
  - Note: Also enable "Include command line in process creation events" under Administrative Templates

### DS Access (for Domain Controllers)
- Audit Directory Service Access: Success and Failure
- Audit Directory Service Changes: Success and Failure

### Logon/Logoff
- Audit Account Lockout: Success and Failure
- Audit Logoff: Success
- Audit Logon: Success and Failure
- Audit Special Logon: Success
- Audit Other Logon/Logoff Events: Success and Failure

### Object Access
- Audit File System: Success and Failure
- Audit Handle Manipulation: Success and Failure
- Audit Registry: Success and Failure
- Audit Kernel Object: Success and Failure
- Audit File Share: Success and Failure
- Audit Detailed File Share: Success and Failure

### Policy Change
- Audit Audit Policy Change: Success and Failure
- Audit Authentication Policy Change: Success and Failure
- Audit MPSSVC Rule-Level Policy Change: Success and Failure
- Audit Other Policy Change Events: Success and Failure

### Privilege Use
- Audit Sensitive Privilege Use: Success and Failure

### System
- Audit Security State Change: Success and Failure
- Audit Security System Extension: Success and Failure
- Audit System Integrity: Success and Failure

## Administrative Templates Settings
Navigate to: Computer Configuration -> Policies -> Administrative Templates

### Windows PowerShell
- Turn on Module Logging
  - Enable
  - Set "Module Names" to *
- Turn on PowerShell Script Block Logging
  - Enable
- Turn on PowerShell Transcription
  - Enable (optional, specify output directory if needed)

### System -> Audit Process Creation
- Include command line in process creation events: Enable

### Windows Components -> Windows Firewall
- Windows Firewall: Display notifications: Enable
- Apply local firewall rules: Enable
- Apply local connection security rules: Enable
- Log dropped packets: Enable
- Log successful connections: Enable

### Task Scheduler
Navigate to: Computer Configuration -> Windows Settings -> Security Settings -> System Services
- Enable Task Scheduler: Automatic

### Security Options
Navigate to: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
- Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings: Enable

### Event Log Settings
Navigate to: Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Event Log Service
- Application log
  - Maximum Log Size (KB): 4194304 (4GB)
  - Retain old events: Enabled
- Security log
  - Maximum Log Size (KB): 4194304 (4GB)
  - Retain old events: Enabled
- System log
  - Maximum Log Size (KB): 4194304 (4GB)
  - Retain old events: Enabled

## Important Notes:
1. After applying these settings, run gpupdate /force on target systems
2. Monitor event log sizes as these settings will generate significant logging
3. Consider implementing log forwarding or centralized logging
4. Some settings may need tuning based on environment size and activity
5. Ensure sufficient disk space for increased logging
6. Consider implementing log rotation or archival policies