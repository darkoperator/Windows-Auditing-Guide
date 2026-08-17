# Windows Advanced Auditing Guide

This guide is a practical reference for configuring, understanding, and collecting Windows Security auditing on workstations, servers, domain controllers, and certificate authorities. It is written for SOC analysts and sysadmins: analysts who need to know what a given event ID actually means and which audit subcategory produces it, and sysadmins who need the exact settings to turn on. The guide exists because most environments encountered during incident response engagements are running Windows with little more than the out-of-the-box default audit policy — logons are barely logged, process creation command lines are off, PowerShell logging is off, and the events an investigation actually needs simply were never generated. This repo is meant to close that gap: a role-by-role baseline you can apply today, plus the event catalog and collection pipeline to make the resulting logs useful.

## Quickstart

For a team starting from zero, the fastest path is:

1. **Pick your role guide** — [`guides/workstation.md`](guides/workstation.md), [`guides/server-baseline.md`](guides/server-baseline.md), [`guides/domain-controller.md`](guides/domain-controller.md), or [`guides/certificate-authority.md`](guides/certificate-authority.md) — matching the machine type you're auditing.
2. **Apply its Baseline settings.** Each role guide points to the underlying `auditpol` and registry data under `settings/`; [`settings/README.md`](settings/README.md) explains exactly how to apply them (`auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback).
3. **Set up collection** so the events you just enabled actually reach a central place to be reviewed. [`collection/windows-event-forwarding.md`](collection/windows-event-forwarding.md) covers the native, agentless path (Windows Event Forwarding); see [`collection/siem-forwarders.md`](collection/siem-forwarders.md) if you need an agent-based alternative instead.

Once baseline logging and collection are in place, use the event catalog and Advanced settings tier in each role guide to go deeper.

## Navigation

| Doc | Description |
|---|---|
| [`event-catalog/full-table.md`](event-catalog/full-table.md) | Full catalog of Windows event IDs covered by this guide — log source, description, criticality, MITRE ATT&CK technique(s), applicable roles, and schema availability. Generated from `event-catalog/events.json`. |
| [`event-catalog/events.json`](event-catalog/events.json) | Source-of-truth machine-readable data behind `full-table.md`. |
| [`settings/README.md`](settings/README.md) | Explains the `settings/` data files and exactly how to apply them (`auditpol`, registry, or GPMC). |
| [`settings/registry-settings.csv`](settings/registry-settings.csv) | Administrative Templates registry values not covered by `auditpol` (PowerShell logging, process creation command line, event log size/retention), applicable to all roles. |
| [`settings/subcategories/workstation-baseline.csv`](settings/subcategories/workstation-baseline.csv) | Baseline `auditpol` subcategory settings for workstations. |
| [`settings/subcategories/workstation-advanced.csv`](settings/subcategories/workstation-advanced.csv) | Advanced `auditpol` subcategory settings for workstations. |
| [`settings/subcategories/server-baseline.csv`](settings/subcategories/server-baseline.csv) | Baseline `auditpol` subcategory settings for member servers. |
| [`settings/subcategories/server-advanced.csv`](settings/subcategories/server-advanced.csv) | Advanced `auditpol` subcategory settings for member servers. |
| [`settings/subcategories/domain-controller-baseline.csv`](settings/subcategories/domain-controller-baseline.csv) | Baseline `auditpol` subcategory settings for domain controllers. |
| [`settings/subcategories/domain-controller-advanced.csv`](settings/subcategories/domain-controller-advanced.csv) | Advanced `auditpol` subcategory settings for domain controllers. |
| [`settings/subcategories/certificate-authority-baseline.csv`](settings/subcategories/certificate-authority-baseline.csv) | Baseline `auditpol` subcategory settings for AD Certificate Services (CA) servers. |
| [`settings/subcategories/certificate-authority-advanced.csv`](settings/subcategories/certificate-authority-advanced.csv) | Advanced `auditpol` subcategory settings for AD Certificate Services (CA) servers. |
| [`guides/workstation.md`](guides/workstation.md) | Auditing guide for domain-joined and standalone Windows 10/11 workstations. |
| [`guides/server-baseline.md`](guides/server-baseline.md) | Auditing guide for general-purpose, domain-joined member servers. |
| [`guides/domain-controller.md`](guides/domain-controller.md) | Auditing guide for Active Directory Domain Controllers. |
| [`guides/certificate-authority.md`](guides/certificate-authority.md) | Auditing guide for AD Certificate Services (AD CS) Certificate Authority servers. |
| [`collection/windows-event-forwarding.md`](collection/windows-event-forwarding.md) | Setting up native Windows Event Forwarding / Windows Event Collector (WEF/WEC) for centralized collection. |
| [`collection/siem-forwarders.md`](collection/siem-forwarders.md) | Shipping Windows event logs to a SIEM via a dedicated agent-based forwarder, as an alternative or complement to WEF. |
| [`collection/sysmon.md`](collection/sysmon.md) | Why Sysmon complements native Windows Security auditing and where its events fit in the collection pipeline. |
| [`collection/xpath-queries.md`](collection/xpath-queries.md) | Consolidated XPath query collection for scoping WEF subscriptions and log queries. |

## Status

The audit settings and event catalog data in this repo are current as of this guide's last update. Applying them today is a manual process — `auditpol /restore`, `reg.exe`/`Set-ItemProperty`, or the GPMC fallback, all documented in [`settings/README.md`](settings/README.md). A PowerShell tool to automate applying these settings end-to-end (restore the right `auditpol` subcategory file, walk `registry-settings.csv`, optionally import into a GPO) is planned but **not yet built**. See the design spec for its intended shape: [`docs/superpowers/specs/2026-08-16-guide-redesign-design.md`](docs/superpowers/specs/2026-08-16-guide-redesign-design.md).
