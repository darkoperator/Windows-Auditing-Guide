# Windows Event Forwarding (WEF/WEC) Setup Guide

Applies to Windows Server 2016+ collectors and Windows Server 2016+ / Windows 10/11 sources. This guide covers standing up centralized event collection using the Windows Event Collector (WEC) role and Windows Event Forwarding (WEF) subscriptions, and how to point those subscriptions at the query collection in [`collection/xpath-queries.md`](xpath-queries.md).

## What WEF/WEC is and when to use it

Windows Event Forwarding is a native Windows feature — no agent, no third-party service — that ships events from a source computer's local event logs to a central collector over WS-Management (the same protocol WinRM uses). The collector side of the pair is the Windows Event Collector role: a Windows service (`Wecsvc`) that either receives pushed events from sources or actively pulls them, and writes everything into a local `ForwardedEvents` log (or another log you designate) that your SIEM or log shipper can then read from a single place instead of reaching out to every endpoint individually.

The main reason to reach for WEF/WEC instead of a log-shipping agent (Winlogbeat, NXLog, a SIEM's native forwarder, etc.) is deployment friction: WEF is built into every supported version of Windows, so there is nothing to install, patch, or license on the source computers — only configuration (a GPO and a few local settings). That makes it a strong fit when:

- You already have, or are willing to stand up, a small number of Windows Event Collector servers and want to avoid deploying and maintaining an agent fleet-wide.
- Your environment is predominantly Active Directory domain-joined, since GPO is the natural distribution mechanism for the subscription configuration.
- You want an intermediate hop that normalizes and buffers events before they reach a SIEM, or you need forwarding as a stopgap while a full agent-based pipeline is being built out.

It's a weaker fit when you need real-time streaming with sub-second latency (WEF batches and has configurable but non-trivial latency), when most of your endpoints are non-domain-joined or outside AD entirely (still possible via HTTPS/certificates, but with meaningfully more setup per host), or when you need to forward more than the event log channels WEF exposes (application-level logs outside the Windows Event Log, for instance).

## Source-initiated vs. collector-initiated subscriptions

WEF supports two subscription models, and the choice determines both how sources learn about the subscription and how the trust relationship is established.

**Source-initiated** subscriptions are the default recommendation for anything beyond a handful of machines. The source computers are told where to send events via a Group Policy setting (`Configure target Subscription Manager`, described below); each source then contacts the collector on its own, at the interval the GPO specifies, and asks whether there is a subscription it should be participating in. The collector's subscription definition doesn't enumerate individual source computers by name — instead it authorizes an SDDL-defined set of computers (typically "Domain Computers" or a specific security group) to enroll. This scales well for large or dynamic fleets: adding a new computer to the domain (or to the authorized group) is enough to have it start forwarding, with no per-machine subscription edit on the collector, and machines that come and go (laptops, VMs, ephemeral cloud instances) don't need to be tracked individually.

**Collector-initiated** subscriptions invert that relationship: the collector is configured with an explicit list of target source computers, and it reaches out to each one to read (pull) its events. This avoids touching Group Policy on the sources at all, which is convenient for a small, static set of high-value machines (a handful of domain controllers or Tier-0 servers, for example) or for a quick proof-of-concept. It doesn't scale well past a modest number of hosts, though, because every addition or removal is a manual edit to the collector's `EventSources` list, and the collector's own credentials (or an explicit `AllowedSourceNonDomainComputers` account) need read access on every one of those sources individually.

As a rule of thumb: pick collector-initiated for a small, stable set of machines you're willing to manage by hand or want running without any GPO changes; pick source-initiated for anything fleet-wide, where the set of machines will grow, shrink, or churn over time.

## Setting up the Windows Event Collector role

### 1. Configure the collector

On the server that will act as the collector, enable the Windows Event Collector service and its default configuration:

```powershell
wecutil qc
```

This sets the `Wecsvc` service to start automatically (delayed start) and starts it immediately; it prompts for confirmation unless you pass `/q`. The collector also needs a running WinRM listener (WEF rides over WS-Management), so if WinRM hasn't already been configured on the box, run `winrm quickconfig` as well — it creates the default HTTP listener on port 5985 and opens the corresponding firewall rule.

### 2. Grant source computers' forwarding service read access to the Security log

The forwarding plugin on each source computer runs as the local `NETWORK SERVICE` account, and by default that account does not have read access to the Security log (only `Event Log Readers`, `Administrators`, and `SYSTEM` do). Since most subscriptions of interest pull from the Security channel, grant `NETWORK SERVICE` explicit read access on **every source computer** (this is most easily done once via the same GPO or script that deploys the rest of your audit configuration):

```powershell
wevtutil sl Security /ca:O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)
```

This is Microsoft's published reference SDDL for granting WEF forwarding read access to the Security log (see Microsoft's "Use Windows Event Forwarding to help with intrusion detection" guidance). It grants `SYSTEM` full control (`0xf0005`, its normal level of access on this channel — do not narrow this to read-only), `BUILTIN\Administrators` read/write (`0x5`), the built-in **Event Log Readers** group (`S-1-5-32-573`) read (`0x1`), and `NETWORK SERVICE` read (`0x1`) — the account the forwarding plugin actually runs as. Run `wevtutil gl Security` first if you want to see the channel's current access descriptor before overwriting it, and confirm no local customization is being clobbered.

If a subscription only reads from logs other than Security (System, Application, the PowerShell operational logs, etc.), this step is usually unnecessary — `NETWORK SERVICE` already has read access to those by default — but Security is the common case, so treat it as a standard part of source onboarding.

### 3. GPO: point sources at the collector (source-initiated only)

For source-initiated subscriptions, sources need to be told where the collector is. This is set via Group Policy, under:

```
Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Event Forwarding -> Configure target Subscription Manager
```

Enable the policy and add one Subscription Manager entry per collector, in the form:

```
Server=http://wec01.corp.example.com:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

- `Server=` is the collector's FQDN and the WinRM port (5985 for HTTP/Kerberos, 5986 for HTTPS — see the transport section below).
- `Refresh=` is the interval, in seconds, at which each source checks back in with the collector for updated subscription configuration (60 seconds is a reasonable starting point for a small/medium environment; raise it for very large fleets to reduce collector load).

Link this GPO to the OUs containing the source computers you want to forward from, and give it time to apply (or force it with `gpupdate /force` on a test machine) before expecting sources to show up. For collector-initiated subscriptions this GPO step is skipped entirely — the collector already knows which sources to contact.

### 4. Create the subscription

Subscriptions are defined in an XML file and loaded with `wecutil cs <subscription.xml>` (create) or `wecutil us <subscription.xml>` (update an existing one by matching `SubscriptionId`). See the worked example below for a complete source-initiated subscription; the same file format is used for collector-initiated subscriptions, substituting `SubscriptionType` (`CollectorInitiated` instead of `SourceInitiated`) and adding an explicit `<EventSources>` list of target computers in place of `AllowedSourceDomainComputers`.

## Transport: Kerberos vs HTTPS/certificate-based

WEF's default and simplest transport is HTTP with Kerberos authentication (WinRM's `Negotiate`/Kerberos mechanism), on port 5985. This works whenever both the source and collector are domain-joined machines within the same Active Directory forest (or forests joined by a two-way trust that supports Kerberos referrals) — Kerberos handles both mutual authentication and encryption of the traffic without any certificates to manage, which is why it's the default recommendation for a typical single-forest environment.

Kerberos stops being usable once machines fall outside that trust boundary:

- **Cross-forest without a suitable trust**, or where Kerberos referrals aren't set up between forests.
- **Non-domain-joined sources** — workgroup machines, DMZ hosts, or anything that simply isn't a member of the AD domain the collector belongs to — since Kerberos requires both ends to be able to authenticate against the same (or a trusting) KDC.

In either case, switch to HTTPS with certificate-based authentication instead: configure a WinRM HTTPS listener (port 5986) on both source and collector using certificates issued by a CA both sides trust, and authenticate sources by client certificate rather than domain credentials. This requires more per-host setup (certificate enrollment and a WinRM HTTPS listener configuration on every source, plus `AllowedSourceNonDomainComputers`/`IssuerCA` configuration on the collector's subscription) but is the only supported path for forwarding from machines that Kerberos can't reach. A common pattern is to use Kerberos for the bulk of the domain-joined fleet and carve out HTTPS-based subscriptions specifically for the non-domain-joined or cross-forest subset.

## Building a subscription with the XPath query collection

Every subscription's `<Query>` element is exactly one of the `QueryList` blocks from [`collection/xpath-queries.md`](xpath-queries.md), wrapped in a `<Subscription>` envelope with the delivery, transport, and authorization settings covered above. Pick the query (or queries — a single subscription can contain multiple `<Query>` elements, each with a different `Path`/`Select`, up to the 20-event-ID-per-query limit noted in that file) that matches what you want this subscription to collect, and paste it in as-is.

### Worked example: forwarding authentication events (source-initiated)

This example forwards the **Authentication Events** query from `collection/xpath-queries.md` (`4624`, `4625`, `4634`, `4647`, `4648`, `4672`, `4768`, `4769`, `4771`, `4776`, `4778`, `4779` — successful/failed logon, logoff, explicit-credential logon, special privilege assignment, Kerberos TGT/service-ticket/pre-auth/NTLM events, and RDP/Terminal Services window-station reconnect/disconnect) from every authorized domain computer into the collector's local `ForwardedEvents` log.

Save this as `forward-authentication-events.xml` and load it with `wecutil cs forward-authentication-events.xml`:

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>Forward-Authentication-Events</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Forwards Security log authentication events (logon/logoff, explicit-credential logon, special privilege use, Kerberos TGT/service ticket) from authorized domain computers.</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>20</MaxItems>
      <MaxLatencyTime>30000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="900000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0" Path="Security">
          <Select Path="Security">
            *[System[(EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or
              (EventID=4648) or (EventID=4672) or (EventID=4768) or (EventID=4769) or
              (EventID=4771) or (EventID=4776) or (EventID=4778) or (EventID=4779)]]
          </Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

Notes on the fields that are easy to get wrong:

- `TransportName` is `HTTP` for Kerberos-authenticated delivery on port 5985, or `HTTPS` for certificate-based delivery on 5986 (see the transport section above) — it must match what the GPO's Subscription Manager URL and the WinRM listener are actually configured for.
- `AllowedSourceDomainComputers` is an SDDL string, not a plain list — the example above authorizes the built-in `Domain Computers` group (`DC`) plus `NETWORK SERVICE` (`NS`, needed for the source's own forwarding plugin). Scope this down to a dedicated security group (e.g., `O:NSG:NSD:(A;;GA;;;S-1-5-21-...-1105)`, where the SID is your group's) if you don't want every domain-joined computer eligible to enroll.
- `ReadExistingEvents=false` means only events generated after the subscription is created are forwarded; set it to `true` for a one-time backfill of the existing log (be mindful of the volume this can generate on first run).
- `Batching` controls latency: events are pushed once either `MaxItems` events have accumulated or `MaxLatencyTime` milliseconds have elapsed, whichever comes first. Lower `MaxLatencyTime` for more near-real-time delivery at the cost of more, smaller network round-trips.

For a collector-initiated version of the same subscription, change `SubscriptionType` to `CollectorInitiated`, drop `AllowedSourceDomainComputers`, and add an explicit source list:

```xml
<EventSources>
  <EventSource Enabled="true">
    <Address>dc01.corp.example.com</Address>
  </EventSource>
  <EventSource Enabled="true">
    <Address>dc02.corp.example.com</Address>
  </EventSource>
</EventSources>
```

## Basic troubleshooting

When a subscription isn't delivering events, check these two operational logs first — one on each end of the pair:

- **On the collector**: `Microsoft-Windows-Eventlog-ForwardingPlugin/Operational` (under Applications and Services Logs -> Microsoft -> Windows -> Eventlog-ForwardingPlugin -> Operational, or `Get-WinEvent -LogName Microsoft-Windows-Eventlog-ForwardingPlugin/Operational`). This is where the collector logs per-source subscription state — a source successfully connecting and beginning delivery, a source going stale (missing its heartbeat), or a source failing to authenticate or authorize against the subscription.
- **On each source**: `Microsoft-Windows-Forwarding/Operational` (`Get-WinEvent -LogName Microsoft-Windows-Forwarding/Operational`). This is where the source-side forwarding plugin logs whether it found a subscription to service (after checking in with the Subscription Manager URL from the GPO), whether it could reach the collector, and any errors reading the local channel the subscription asks for (commonly, the `wevtutil sl` access-control step above being missed for a Security-log subscription).

Beyond those two logs, a short checklist for the common failure modes:

1. **No subscription showing up on a source at all**: confirm the `Configure target Subscription Manager` GPO has actually applied (`gpresult /r` or `rsop.msc` on the source) and that the `Refresh` interval has elapsed since the GPO landed.
2. **Source connects but nothing is delivered**: check `wecutil gr <SubscriptionId>` on the collector — it reports per-source runtime status (`Active`, `Error`, error codes) without needing to dig through the event log.
3. **Access denied / events missing specifically from the Security log**: revisit the `wevtutil sl Security /ca:...` step — this is the single most common cause of a subscription that "works" (source shows Active) but delivers zero Security events.
4. **Kerberos authentication failures across a forest boundary**: this is expected — see the transport section above; switch that subscription's sources to an HTTPS/certificate-based listener rather than troubleshooting Kerberos further.
5. **Firewall**: confirm the WinRM port in use (5985 or 5986) is open inbound on whichever side is receiving the connection — the collector for push/source-initiated delivery, the source for pull/collector-initiated delivery.
