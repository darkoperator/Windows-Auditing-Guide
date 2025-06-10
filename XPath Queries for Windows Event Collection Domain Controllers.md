# XPath Queries for Windows Event Collection Domain Controllers

## Security Events
```xml
<!-- Authentication Events (Logon/Logoff) -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4648) or (EventID=4672) or (EventID=4776) or (EventID=4771) or (EventID=4768) or (EventID=4769)]]
    </Select>
  </Query>
</QueryList>

<!-- Account Management -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4738) or (EventID=4740) or (EventID=4767) or (EventID=4781)]]
    </Select>
  </Query>
</QueryList>

<!-- Group Management -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4728) or (EventID=4729) or (EventID=4732) or (EventID=4733) or (EventID=4756) or (EventID=4757)]]
    </Select>
  </Query>
</QueryList>

<!-- Process Creation with Command Line -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4688)]] and *[EventData[Data[@Name='CommandLine']]]
    </Select>
  </Query>
</QueryList>

<!-- Scheduled Tasks -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4698) or (EventID=4699) or (EventID=4700) or (EventID=4701) or (EventID=4702)]]
    </Select>
  </Query>
</QueryList>

<!-- Object Access (including LSASS) -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4656) or (EventID=4663) or (EventID=4658) or (EventID=4660) or (EventID=4670)]]
    </Select>
  </Query>
</QueryList>
```

## PowerShell Events
```xml
<!-- PowerShell Operational -->
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-PowerShell/Operational">
      *[System[(EventID=4103) or (EventID=4104)]]
    </Select>
  </Query>
</QueryList>

<!-- Windows PowerShell -->
<QueryList>
  <Query Id="0">
    <Select Path="Windows PowerShell">
      *[System[(EventID=403)]]
    </Select>
  </Query>
</QueryList>
```

## Remote Desktop Events
```xml
<!-- RDP Local Session Manager -->
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">
      *[System[(EventID=21) or (EventID=22) or (EventID=23) or (EventID=24) or (EventID=25)]]
    </Select>
  </Query>
</QueryList>

<!-- RDP Remote Connection -->
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">
      *[System[(EventID=1149)]]
    </Select>
  </Query>
</QueryList>
```

## Directory Service Events
```xml
<!-- Active Directory Changes -->
<QueryList>
  <Query Id="0">
    <Select Path="Directory Service">
      *[System[(EventID=4662) or (EventID=5136) or (EventID=5137) or (EventID=5138) or (EventID=5139) or (EventID=5141)]]
    </Select>
  </Query>
</QueryList>
```

## File Share Events
```xml
<!-- File Share Access -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=5140) or (EventID=5145)]]
    </Select>
  </Query>
</QueryList>
```

## Windows Firewall Events
```xml
<!-- Firewall Changes -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4946) or (EventID=4947) or (EventID=4948) or (EventID=4950) or (EventID=4954) or (EventID=4956)]]
    </Select>
  </Query>
</QueryList>

<!-- Firewall Blocking -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=5031) or (EventID=5152) or (EventID=5153) or (EventID=5155) or (EventID=5157)]]
    </Select>
  </Query>
</QueryList>
```

## System Events
```xml
<!-- Critical System Events -->
<QueryList>
  <Query Id="0">
    <Select Path="System">
      *[System[(EventID=1102) or (EventID=6005) or (EventID=6006) or (EventID=7040) or (EventID=7045)]]
    </Select>
  </Query>
</QueryList>
```

## Usage Examples:

1. Using wevtutil:
```batch
wevtutil qe Security "/q:*[System[(EventID=4624)]]" /f:text
```

2. Using Get-WinEvent:
```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4624)]]'
```

3. For WEF Subscription:
```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <Query>
        <QueryList>
            <!-- Insert query from above -->
        </QueryList>
    </Query>
    <!-- Add other subscription properties -->
</Subscription>
```

## Notes:
- These queries can be used in:
  - Windows Event Forwarding (WEF) subscriptions
  - Event Log queries
  - Log collection tools
- Consider performance impact when using complex queries
- Test queries before implementing in production
- Some events may require specific audit policies to be enabled
- Add additional filtering based on your environment's needs