# XPath Query Collection for Windows Event Collection

## Security Log Queries

### Authentication Events
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or 
        (EventID=4648) or (EventID=4672) or (EventID=4768) or (EventID=4769) or 
        (EventID=4771) or (EventID=4776) or (EventID=4778) or (EventID=4779)]]
    </Select>
  </Query>
</QueryList>
```

### Account Management Events
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or 
        (EventID=4725) or (EventID=4726) or (EventID=4728) or (EventID=4729) or 
        (EventID=4732) or (EventID=4733) or (EventID=4738) or (EventID=4740) or 
        (EventID=4767)]]
    </Select>
  </Query>
</QueryList>
```

### Object Access Events
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4656) or (EventID=4657) or (EventID=4658) or (EventID=4660) or 
        (EventID=4663) or (EventID=4670) or (EventID=5140) or (EventID=5142) or 
        (EventID=5145)]]
    </Select>
  </Query>
</QueryList>
```

### Process and Program Events
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688) or (EventID=4689) or (EventID=4696) or (EventID=4697) or 
        (EventID=4698) or (EventID=4699) or (EventID=4700) or (EventID=4701) or 
        (EventID=4702)]]
    </Select>
  </Query>
</QueryList>
```

### Certificate Services Events 1
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4868) or (EventID=4869) or (EventID=4870) or (EventID=4871) or 
        (EventID=4872) or (EventID=4873) or (EventID=4874) or (EventID=4875) or 
        (EventID=4876) or (EventID=4877) or (EventID=4878) or (EventID=4879) or 
        (EventID=4880) or (EventID=4881) or (EventID=4882) or (EventID=4883) or 
        (EventID=4884) or (EventID=4885) or (EventID=4886) or (EventID=4887)]]
    </Select>
  </Query>
</QueryList>
```

### Certificate Services Events 2
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4888) or (EventID=4889) or (EventID=4890) or (EventID=4891) or 
        (EventID=4892) or (EventID=4893) or (EventID=4894) or (EventID=4895) or 
        (EventID=4896) or (EventID=4897) or (EventID=4898)]]
    </Select>
  </Query>
</QueryList>
```

### Firewall Events
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4946) or (EventID=4947) or (EventID=4948) or (EventID=4950) or 
        (EventID=4954) or (EventID=4956) or (EventID=5024) or (EventID=5025) or 
        (EventID=5031) or (EventID=5152) or (EventID=5153) or (EventID=5155) or 
        (EventID=5157)]]
    </Select>
  </Query>
</QueryList>
```

## System Log Queries

### Service Operations
```xml
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[(EventID=7022) or (EventID=7023) or (EventID=7024) or (EventID=7026) or 
        (EventID=7031) or (EventID=7034) or (EventID=7040) or (EventID=7045)]]
    </Select>
  </Query>
</QueryList>
```

## PowerShell Operational Log
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">
      *[System[(EventID=4103) or (EventID=4104)]]
    </Select>
  </Query>
</QueryList>
```

## Windows PowerShell Log
```xml
<QueryList>
  <Query Id="0" Path="Windows PowerShell">
    <Select Path="Windows PowerShell">
      *[System[(EventID=403)]]
    </Select>
  </Query>
</QueryList>
```

## WMI-Activity Operational Log
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-WMI-Activity/Operational">
    <Select Path="Microsoft-Windows-WMI-Activity/Operational">
      *[System[(EventID=5857) or (EventID=5858) or (EventID=5859) or (EventID=5860) or 
        (EventID=5861)]]
    </Select>
  </Query>
</QueryList>
```

## RDP/Terminal Services Logs

### LocalSessionManager Operational
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">
    <Select Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">
      *[System[(EventID=21) or (EventID=22) or (EventID=23) or (EventID=24) or 
        (EventID=25) or (EventID=39) or (EventID=40)]]
    </Select>
  </Query>
</QueryList>
```

### RemoteConnectionManager Operational
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">
    <Select Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">
      *[System[(EventID=1149)]]
    </Select>
  </Query>
</QueryList>
```

## Windows Defender Operational
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">
      *[System[(EventID=1006) or (EventID=1007) or (EventID=1008) or (EventID=1015) or 
        (EventID=1116) or (EventID=1117) or (EventID=1118) or (EventID=5001) or 
        (EventID=5004) or (EventID=5007) or (EventID=5010)]]
    </Select>
  </Query>
</QueryList>
```

## Usage Examples:

### Using wevtutil:
```batch
wevtutil qe Security "/q:<QueryList><Query Id='0'><Select Path='Security'>*[System[(EventID=4624)]]</Select></Query></QueryList>" /f:text
```

### Using Get-WinEvent:
```powershell
Get-WinEvent -FilterXPath "*[System[(EventID=4624)]]" -LogName Security
```

### Using Windows Event Forwarding:
```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <Query>
        <!-- Insert query from above -->
    </Query>
    <!-- Add other subscription properties -->
</Subscription>
```

## Notes:
1. Each query is limited to 20 event IDs per Windows limitations
2. Queries can be combined in WEF subscriptions as needed
3. Test queries before implementing in production
4. Consider performance impact of complex queries
5. Adjust based on your environment's needs
6. Some events require specific audit policies to be enabled
7. Consider log size and retention policies

## Best Practices:
1. Test queries in test environment first
2. Monitor performance impact
3. Implement log rotation
4. Use centralized logging
5. Regular review and tuning
6. Document customizations