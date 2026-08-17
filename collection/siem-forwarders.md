# Agent-Based Log Forwarding to a SIEM

Applies to Windows Server 2016+ and Windows 10/11. This guide covers shipping Windows event logs to a SIEM or log analytics platform using a dedicated forwarding agent installed on each endpoint, as an alternative or complement to native [Windows Event Forwarding](windows-event-forwarding.md).

## When to choose an agent over WEF

[Windows Event Forwarding](windows-event-forwarding.md) is the default recommendation for centralizing logs within a single Active Directory environment — it's built into Windows, requires no third-party software, and needs only GPO-driven configuration. An agent-based forwarder is the right call instead when one of the following applies:

- **You already run a SIEM or EDR product that ships its own forwarder.** Most commercial SIEM and EDR platforms include a lightweight agent as part of the deployment, and standing up a separate WEF/WEC infrastructure alongside it is redundant work for no added benefit — just point the agent you already have at the Security log (and any other channels you need) and skip WEF entirely.
- **You need enrichment or parsing at the edge.** WEF forwards raw or rendered event XML with no transformation. If you need field extraction, tagging with asset metadata, filtering based on event content rather than just event ID, or format conversion (to JSON, CEF, or another structured format) before the event leaves the host, that logic has to live in an agent — WEF has no equivalent capability.
- **You need multi-destination fan-out.** WEF subscriptions deliver to a single collector (or a single log on a single collector). An agent can typically be configured to ship the same event stream to more than one destination simultaneously — for example, a primary SIEM and a long-term storage/archive target — without needing a second collection tier.
- **Your destination is outside the AD trust boundary entirely**, most commonly a cloud-hosted SIEM or log analytics service. WEF/WEC is designed for collector servers reachable over WS-Management within (or federated with) your AD forest; a cloud destination usually expects an agent that authenticates outbound over HTTPS to a cloud API instead.

None of this rules out running both: it's common to use WEF to centralize logs onto a small number of collector servers and then run a single forwarding agent on those collectors (rather than on every endpoint) to ship the aggregated `ForwardedEvents` log onward to a SIEM. That combines WEF's zero-footprint collection with an agent's flexibility on the delivery side, while keeping the agent footprint limited to a handful of servers instead of the whole fleet.

The rest of this guide covers three commonly used forwarding agents at a basic install/configuration level. Each vendor's own documentation is the authoritative reference for configuration syntax, sizing, and troubleshooting — the goal here is orientation, not a full configuration reference.

## Winlogbeat

[Winlogbeat](https://www.elastic.co/beats/winlogbeat) is Elastic's lightweight Windows event log shipper, part of the Beats family, built to ship events to Elasticsearch (directly or via Logstash) or any other destination Elastic's output modules support.

Winlogbeat installs as a Windows service and reads its configuration from `winlogbeat.yml`. The core of that configuration is the `event_logs` list, where each entry names a channel to collect from (for example, `Security`, `System`, `Application`, or one of the operational logs such as `Microsoft-Windows-PowerShell/Operational`) along with optional per-channel settings like an XPath-based event filter. Beyond the `event_logs` list, the configuration also defines one or more `output` blocks (Elasticsearch, Logstash, Kafka, etc.) that control where collected events are sent.

Installation is a matter of downloading the Winlogbeat package for the target architecture, extracting it, editing `winlogbeat.yml` to list the channels and output you need, and registering it as a service (Elastic ships a PowerShell install script for this in the download). For the full configuration reference — every `event_logs` option, output types, module-based parsing for common event sources, and upgrade guidance — see [Elastic's official Winlogbeat documentation](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html).

## Splunk Universal Forwarder

The [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html) is Splunk's lightweight forwarding agent, used to collect data (including Windows event logs) and ship it to a Splunk indexer.

Windows event log collection is configured through `inputs.conf`, using `WinEventLog://` stanzas — one per channel to be monitored. A stanza such as `[WinEventLog://Security]` enables collection from the Security log, with stanza-level settings available to control things like whether to start from existing events or only new ones, event ID filtering, and the index the data should land in on the indexer side. `inputs.conf` can be deployed to forwarders individually or, more commonly at scale, pushed out centrally via a Splunk deployment server so that a single app defines collection configuration for the whole forwarder fleet.

Installation follows the standard Splunk pattern: install the Universal Forwarder package, configure it (directly or via deployment server) with the indexer(s) to forward to and the `WinEventLog` stanzas to collect from, and start the forwarder service. For the full configuration reference — every `inputs.conf` option, deployment server setup, and forwarder management at scale — see [Splunk's official Universal Forwarder documentation](https://docs.splunk.com/Documentation/Forwarder).

## Azure Monitor Agent (AMA)

The [Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview) is Microsoft's current-generation agent for shipping telemetry, including Windows event logs, to Azure Monitor Log Analytics workspaces and Microsoft Sentinel. It replaces the older Log Analytics (MMA) and Azure Diagnostics agents, both of which are on a deprecation path.

AMA differs from Winlogbeat and the Splunk Universal Forwarder in how it's configured: rather than editing a local file on each machine, what the agent collects and where it sends that data is defined centrally in Azure as a **Data Collection Rule (DCR)**, which is then associated with the target machines (Azure VMs, Azure Arc-enabled servers, or VM scale sets). The DCR specifies the event log channels and XPath queries to collect from, along with the destination workspace or table; associating the DCR with a machine is what causes the locally installed agent to start collecting according to that rule, without any local configuration file to maintain per host.

Deploying AMA is a two-part process: install the agent extension on each target machine (via the Azure portal, Azure Policy for fleet-wide rollout, ARM/Bicep templates, or the Azure CLI), and create and associate a Data Collection Rule that defines the Windows event log collection you want. This is the natural choice when the destination is Sentinel or a Log Analytics workspace, since it's the Microsoft-supported path and integrates directly with DCR-based data transformation. For the full configuration reference — DCR schema, supported data sources, and Sentinel-specific onboarding — see [Microsoft's official Azure Monitor Agent documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview).

## Decision note: don't duplicate WEF for free

Within a single Active Directory environment, agent-based forwarding largely duplicates what WEF already provides at no cost — both get Windows event log data off the source machine and onto a central destination. Deploying an agent fleet-wide when WEF would do the job means taking on installation, patching, and licensing overhead (depending on the agent) that WEF simply doesn't have.

The two things WEF genuinely can't do are the two things that justify reaching for an agent instead: forwarding to a **destination WEF can't reach natively** (a cloud SIEM or Log Analytics workspace, reachable over HTTPS rather than WS-Management within the AD trust boundary), and **enrichment or parsing you can't get from raw XML** (field extraction, tagging, format conversion, or filtering beyond what an XPath query on event ID and system fields can express). If neither applies, WEF/WEC — covered in [`collection/windows-event-forwarding.md`](windows-event-forwarding.md) — is the lower-overhead choice. If either applies, pick the agent above that matches your destination and use its vendor documentation for the full configuration walkthrough.
