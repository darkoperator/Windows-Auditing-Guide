# Active Directory Certificate Authority Event ID Collection Guide

## Security Log Events

| Event ID | Description | Criticality | MITRE Technique IDs |
|----------|-------------|-------------|-------------|
| 4868 | Certificate Manager denied a pending certificate request | High | T1552.004 - Private Keys |
| 4869 | Certificate Services received a resubmitted certificate request | High | T1552.004 - Private Keys |
| 4870 | Certificate Services revoked a certificate | High | T1552.004 - Private Keys |
| 4871 | Certificate Services received a request to publish CRL | Medium | T1552.004 - Private Keys |
| 4872 | Certificate Services published the CA certificate to AD DS | Medium | T1552.004 - Private Keys |
| 4873 | Certificate request extension changed | High | T1552.004 - Private Keys |
| 4874 | One or more certificate request attributes changed | High | T1552.004 - Private Keys |
| 4875 | Certificate Services received a request to shut down | High | T1562 - Impair Defenses |
| 4876 | Certificate Services backup started | Medium | T1552.004 - Private Keys |
| 4877 | Certificate Services backup completed | Medium | T1552.004 - Private Keys |
| 4878 | Certificate Services restore started | High | T1552.004 - Private Keys |
| 4879 | Certificate Services restore completed | High | T1552.004 - Private Keys |
| 4880 | Certificate Services started | Medium | T1552.004 - Private Keys |
| 4881 | Certificate Services stopped | High | T1562 - Impair Defenses |
| 4882 | Security permissions on CA changed | High | T1222 - File and Directory Permissions Modification |
| 4883 | Certificate Services retrieved an archived key | High | T1552.004 - Private Keys |
| 4884 | Certificate Services imported a certificate into its database | High | T1552.004 - Private Keys |
| 4885 | The audit filter for Certificate Services changed | High | T1562.002 - Disable Windows Event Logging |
| 4886 | Certificate Services received a certificate request | Medium | T1552.004 - Private Keys |
| 4887 | Certificate Services approved a certificate request and issued certificate | High | T1552.004 - Private Keys |
| 4888 | Certificate Services denied a certificate request | Medium | T1552.004 - Private Keys |
| 4889 | Certificate Services set the status of a certificate request to pending | Medium | T1552.004 - Private Keys |
| 4890 | Certificate Manager settings changed | High | T1562 - Impair Defenses |
| 4891 | Configuration entry changed in Certificate Services | High | T1562 - Impair Defenses |
| 4892 | Property of Certificate Services changed | High | T1562 - Impair Defenses |
| 4893 | Certificate Services archived a key | High | T1552.004 - Private Keys |
| 4894 | Certificate Services imported and archived a key | High | T1552.004 - Private Keys |
| 4895 | Certificate Services published CA certificate to AD DS | Medium | T1552.004 - Private Keys |
| 4896 | Row in certificate database marked as deleted | High | T1485 - Data Destruction |
| 4897 | Role separation enabled | High | T1548 - Abuse Elevation Control Mechanism |
| 4898 | Certificate Services loaded a template | Medium | T1552.004 - Private Keys |

## Microsoft-Windows-CertificationAuthority Events

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

## Notes:
- Criticality levels:
  - High: Critical security events that should always be monitored
  - Medium: Important events that provide valuable context
- MITRE ATT&CK Technique IDs help map events to known adversary tactics and techniques
- All events should be collected with their full details
- Pay special attention to:
  - Certificate issuance events
  - Certificate template modifications
  - Private key operations
  - Permission changes
  - CA configuration changes
  - Service starts/stops
  - Audit policy changes

## Key Monitoring Scenarios:
1. Certificate theft attempts
2. Unauthorized template modifications
3. Privilege escalation via certificates
4. CA service tampering
5. Unauthorized certificate issuance
6. Private key archival operations
7. CA backup/restore operations
8. Permission changes on CA
9. Template deployment changes
10. CRL publication issues