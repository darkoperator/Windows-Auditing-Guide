# Certificate Authority Server Security Event Logging GPO Configuration Guide

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

### Logon/Logoff
- Audit Account Lockout: Success and Failure
- Audit Group Membership: Success
- Audit Logoff: Success
- Audit Logon: Success and Failure
- Audit Other Logon/Logoff Events: Success and Failure
- Audit Special Logon: Success and Failure

### Object Access
- Audit Certification Services: Success and Failure
- Audit Detailed File Share: Success and Failure
- Audit File Share: Success and Failure
- Audit File System: Success and Failure
- Audit Handle Manipulation: Success and Failure
- Audit Kernel Object: Success and Failure
- Audit Other Object Access Events: Success and Failure
- Audit Registry: Success and Failure
- Audit SAM: Success and Failure

### Policy Change
- Audit Audit Policy Change: Success and Failure
- Audit Authentication Policy Change: Success and Failure
- Audit Authorization Policy Change: Success and Failure
- Audit MPSSVC Rule-Level Policy Change: Success and Failure
- Audit Other Policy Change Events: Success and Failure

### Privilege Use
- Audit Sensitive Privilege Use: Success and Failure

### System
- Audit Security State Change: Success and Failure
- Audit Security System Extension: Success and Failure
- Audit System Integrity: Success and Failure

## Certificate Services Specific Events to Monitor
Enable auditing for these Certificate Services events:

### Certificate Services Operations
- Certificate Manager Settings: Success and Failure
- Certificate Services: Success and Failure
- Store and Retrieve Archived Keys: Success and Failure
- Backup and Restore CA Database: Success and Failure
- Change CA Configuration: Success and Failure
- Change CA Security Settings: Success and Failure
- Issue and Manage Certificate Requests: Success and Failure
- Revoke Certificates and Publish CRLs: Success and Failure
- Start and Stop Certificate Services: Success and Failure

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

### Event Log Service Settings
Navigate to: Computer Configuration → Administrative Templates → Windows Components → Event Log Service

### Security Log
- Maximum Log Size (KB): 8388608 (8GB)
- Retain old events: Enabled
- When maximum event log size is reached: Do not overwrite events (Clear log manually)

### System Log
- Maximum Log Size (KB): 4194304 (4GB)
- Retain old events: Enabled
- When maximum event log size is reached: Do not overwrite events (Clear log manually)

### Application Log
- Maximum Log Size (KB): 4194304 (4GB)
- Retain old events: Enabled
- When maximum event log size is reached: Do not overwrite events (Clear log manually)

### Certificate Services Log
Enable logging in the following locations:
- Microsoft-Windows-CertificationAuthority/Operational
- Microsoft-Windows-CertificationAuthority/Backup
- Microsoft-Windows-CertificationAuthority/Debug

## Certificate Services Configuration
Navigate to: Computer Configuration → Windows Settings → Security Settings → System Services

### Service Configuration
- Certificate Services: Automatic
- Certificate Propagation: Automatic
- Key Storage Service: Automatic
- Remote Registry: Disabled
- Task Scheduler: Automatic

### Security Options
- Network access: Do not allow anonymous enumeration of SAM accounts and shares: Enabled
- Network security: Configure encryption types allowed for Kerberos: AES only
- Network security: LDAP client signing requirements: Require signing
- System cryptography: Force strong key protection for user keys stored on the computer: User must enter password each time they use a key
- System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing: Enabled

## Windows Firewall Configuration
Enable only required ports for CA operations:

### Inbound Rules
- TCP 135 (RPC Endpoint Mapper)
- TCP 80/443 (HTTP/HTTPS for CRL/AIA)
- TCP 445 (SMB for file-based publishing)
- TCP Dynamic RPC ports (if needed)
- ICMP Echo Request (for monitoring)

### Outbound Rules
- Restrict outbound connections
- Allow only necessary ports for AD replication and CRL publishing

## Additional Security Settings

### Windows Remote Management
- Disable WinRM if not required
- If required, configure with:
  - HTTPS only
  - Negotiate authentication only
  - No basic authentication
  - No unencrypted traffic

### Remote Desktop
- Enable NLA
- Restrict to specific IP addresses
- Enable TLS 1.2/1.3 only
- Disable older cipher suites

## Important Notes:
1. After applying these settings, run gpupdate /force
2. Monitor event log sizes closely
3. Implement centralized logging
4. Regular backup of CA database and private keys
5. Regular review of CA security settings
6. Monitor CRL/AIA accessibility
7. Regular audit of issued certificates

## Best Practices:
1. Implement physical security controls
2. Use HSM for key storage when possible
3. Regular security assessments
4. Maintain offline root CA if using hierarchical PKI
5. Regular review of certificate templates
6. Monitor certificate requests and issuance patterns
7. Regular backup of event logs
8. Implement notifications for critical events

## Critical Events to Monitor:
1. CA service starts/stops
2. Certificate issuance
3. Template modifications
4. Security permission changes
5. Private key operations
6. CRL publication failures
7. Backup/restore operations
8. Policy changes
9. Role separation changes
10. Audit policy modifications

## Role-Specific Hardening:
1. Remove unnecessary roles/features
2. Disable unnecessary services
3. Regular updates and patches
4. Application whitelisting
5. USB device restrictions
6. Network isolation
7. Time synchronization
8. Certificate template hardening