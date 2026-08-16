# Windows Advanced Auditing Guide — Redesign Design

## Context

This repository is an early first pass at a Windows Advanced Auditing guide targeted at SOC analysts and sysadmins. The author works in incident response and repeatedly sees victim organizations without basic Windows auditing/logging in place. The goal is a practical guide covering: which Advanced Audit Policy settings to enable, which events/logs to collect, and how to collect them (WEF, SIEM forwarders, Sysmon) — informed by Microsoft's [Security Auditing overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/security-auditing-overview) (schema/field/version reference, no longer actively updated by Microsoft).

A later, separate phase will build a PowerShell tool to apply/import these audit settings (potentially via existing GPOs). This design covers only the guide's content and structure; the PowerShell tooling is out of scope here and will be designed once the guide's settings are finalized.

### Current state (before this redesign)

11 flat markdown files in the repo root, with significant duplication:

- `Master Windows Event ID Reference Table.md` — event ID table (ID/log/description/criticality/MITRE/applicable role), duplicated across role-specific guides
- `Windows Workstation Event ID Collection Guide.md` / `Windows Workstation Security Event Logging GPO Configuration Guide.md`
- `Windows Server Baseline Event ID Collection Guide.md` / `Windows Server Baseline Security Event Logging GPO Configuration Guide.md`
- `Domain Controller Event ID Collection Guide.md`
- `Active Directory Certificate Authority Event ID Collection Guide.md` / `Certificate Authority Server Security Event Logging GPO Configuration Guide.md`
- `Group Policy Audit Settings Configuration Guide.md` — full Advanced Audit Policy + Administrative Templates checklist
- `XPath Queries for Windows Event Collection Domain Controllers.md` / `XPath Query Collection for Windows Event Collection.md` — overlapping XPath query collections

No README/index ties these together. No structured/machine-readable settings data exists. No Sysmon or non-WEF collection guidance exists.

## Goals

1. Eliminate duplication via a single source of truth for event data and audit settings.
2. Add a Baseline/Advanced maturity tiering so under-resourced teams can triage (address the "victims lack the basics" problem directly).
3. Add field-level schema documentation (from the MS auditing overview page) for a curated set of critical events.
4. Cover additional collection strategies beyond WEF: SIEM agent forwarders, and a bridge to the existing Sysmon Community Guide.
5. Structure the settings data so a later PowerShell tool can consume it directly, reusing native Windows mechanisms (`auditpol` backup/restore) rather than inventing a custom format.

## Non-goals

- Building the PowerShell import/apply tool (future phase).
- Writing new Sysmon deployment/configuration content — the author's existing [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) already covers this in depth; this guide links to it instead of duplicating it.
- Covering Windows Server 2012 R2 or older, or Windows versions prior to 10/11 (current LTS-ish baseline: Server 2016+ and Windows 10/11), except noting version-introduced field differences where relevant.
- Syslog/CEF forwarding (not selected as an in-scope collection method for this pass).

## Repo structure

```
/README.md                          # entry point: what this is, how to navigate, quickstart
/event-catalog/
    events.json                     # single source of truth for all event IDs
    full-table.md                   # generated flat view of events.json, for GitHub readers
/settings/
    subcategories/                  # auditpol-restorable CSVs, one per role+tier
        workstation-baseline.csv
        workstation-advanced.csv
        server-baseline.csv
        server-advanced.csv
        domain-controller-baseline.csv
        domain-controller-advanced.csv
        certificate-authority-baseline.csv
        certificate-authority-advanced.csv
    registry-settings.csv           # Administrative Templates items (role+tier as columns)
    README.md                       # explains the auditpol CSV + registry table mechanism,
                                     # and manual GPMC navigation as a fallback
/guides/
    workstation.md
    server-baseline.md
    domain-controller.md
    certificate-authority.md
/collection/
    windows-event-forwarding.md     # WEF/WEC setup + subscriptions
    siem-forwarders.md              # Winlogbeat / Splunk UF / AMA
    sysmon.md                       # short bridge doc -> Sysmon Community Guide
    xpath-queries.md                # consolidated, replaces the two existing XPath files
```

## Data model

### `event-catalog/events.json`

One JSON record per event ID — the single source of truth for the event catalog. Example (summary-level record):

```json
{
  "eventId": 4688,
  "logSource": "Security",
  "description": "Process creation",
  "criticality": "High",
  "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
  "applicableRoles": ["workstation", "server", "domain-controller", "certificate-authority"],
  "requiredSubcategory": "Detailed Tracking > Process Creation",
  "schema": null
}
```

For the curated critical subset (~15-25 events, see "Event catalog scope" below), `schema` is populated:

```json
"schema": {
  "minVersion": "Windows 10 / Server 2016",
  "fields": [
    {"name": "SubjectUserSid", "description": "SID of account that requested the process"},
    {"name": "NewProcessId", "description": "Handle to the newly created process"},
    {"name": "CommandLine", "description": "Full command line (requires 'Include command line' policy)"}
  ]
}
```

Role guides render their filtered view of this catalog (by `applicableRoles`) rather than maintaining their own copies. `event-catalog/full-table.md` is a checked-in generated flat markdown view of the whole catalog, so GitHub readers don't need tooling to browse it.

### `settings/subcategories/*.csv`

Shaped exactly like `auditpol /backup /file:X.csv` output (columns: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting, Setting Value), one file per role+tier combination. Directly restorable via `auditpol /restore /file:X.csv` — no custom parsing needed by future tooling.

### `settings/registry-settings.csv`

One row per Administrative Templates setting not covered by `auditpol` (PowerShell Module/ScriptBlock logging, `ProcessCreationIncludeCmdLine_Enabled`, event log MaxSize/Retention, Windows Firewall logging paths, etc.). Columns: `Role, Tier, Hive, KeyPath, ValueName, Type, Data, Description`. A future PowerShell tool applies this via `reg.exe` or `Set-ItemProperty`.

## Content strategy

### Maturity tiers

- **Baseline**: minimum viable set, low log volume — logon/auth, account/group management, process creation, audit-log tampering, PowerShell logging, scheduled tasks. The "do this even if nothing else" tier for under-resourced teams.
- **Advanced**: adds object access, detailed file share, registry auditing, WMI, firewall change auditing, DPAPI, kernel object access. Higher volume; requires storage/SIEM planning.

Each role guide presents both tiers so a team can see exactly what they gain moving from Baseline to Advanced.

### Role guides

Unified template for `guides/workstation.md`, `guides/server-baseline.md`, `guides/domain-controller.md`, `guides/certificate-authority.md`:

1. Scope — what this role is, why it matters
2. Baseline settings — narrative + link to `settings/subcategories/<role>-baseline.csv`
3. Advanced settings — narrative + link to `settings/subcategories/<role>-advanced.csv`
4. Event table — filtered view of `event-catalog/events.json` for this role
5. Role-specific notes (e.g. DC gets Directory Service Access events, CA gets private-key/template/issuance events)

This folds the current GPO-guide + event-ID-guide file pairs into one document per role, removing the 1:1 duplication that exists today (e.g. `Windows Server Baseline Event ID Collection Guide.md` + `Windows Server Baseline Security Event Logging GPO Configuration Guide.md` → `guides/server-baseline.md`).

### Collection strategy docs

- `collection/windows-event-forwarding.md` — WEC/WEF setup end-to-end (subscription config, source-initiated vs collector-initiated, Kerberos/HTTPS considerations), referencing `collection/xpath-queries.md` for the actual queries.
- `collection/xpath-queries.md` — consolidation of the two existing XPath files, deduplicated.
- `collection/siem-forwarders.md` — when to choose an agent (Winlogbeat, Splunk Universal Forwarder, Azure Monitor Agent) over WEF, install/config basics, pointing to each vendor's own docs rather than reproducing them.
- `collection/sysmon.md` — short bridge doc: why Sysmon complements native Windows auditing (covers gaps like network connections, image loads, raw access reads, DNS queries that Security log auditing doesn't reach), how its operational log fits into the same WEF/SIEM-forwarder collection pipeline as everything else in this guide, then links out to the author's existing [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) for install/config/event-by-event detail. No Sysmon deployment or event content is duplicated here.

### Event catalog scope

- Full catalog (~80+ events, expanded with the DC/CA-specific events currently only in their separate guides) stays at summary level (ID, log source, description, criticality, MITRE mapping, applicable roles, required subcategory).
- Full field-by-field schema (from the MS Security Auditing overview page) is added only for a curated critical subset of ~15-25 events — the highest-value ones for IR/detection (e.g. 4624/4625, 4688, 4768/4769, 4670, 5140, 4720, 4672, 4698, 1102).
- Version scope: Windows Server 2016+ and Windows 10/11. Version-introduced field differences are noted only where they matter (e.g. a field added in a later build), not exhaustively tracked across every legacy version.

## Migration plan

| Existing file | Fate |
|---|---|
| `Master Windows Event ID Reference Table.md` | Content extracted into `event-catalog/events.json`; file removed, replaced by generated `event-catalog/full-table.md` |
| `Windows Workstation Event ID Collection Guide.md` + `Windows Workstation Security Event Logging GPO Configuration Guide.md` | Merged into `guides/workstation.md`; event data → `events.json`, settings → `settings/subcategories/workstation-*.csv` + `registry-settings.csv` |
| `Windows Server Baseline Event ID Collection Guide.md` + `Windows Server Baseline Security Event Logging GPO Configuration Guide.md` | Merged into `guides/server-baseline.md`, same split |
| `Domain Controller Event ID Collection Guide.md` | Becomes `guides/domain-controller.md`; settings extracted from `Group Policy Audit Settings Configuration Guide.md`'s DS Access section (no separate DC GPO guide exists today) |
| `Active Directory Certificate Authority Event ID Collection Guide.md` + `Certificate Authority Server Security Event Logging GPO Configuration Guide.md` | Merged into `guides/certificate-authority.md` |
| `Group Policy Audit Settings Configuration Guide.md` | Superseded — becomes the source for `settings/` CSVs; `settings/README.md` explains the auditpol CSV + registry table mechanism and manual GPMC navigation as a fallback |
| `XPath Queries for Windows Event Collection Domain Controllers.md` + `XPath Query Collection for Windows Event Collection.md` | Merged into `collection/xpath-queries.md`, deduplicated, referenced from `collection/windows-event-forwarding.md` |

New files not derived from existing content: top-level `README.md`, `collection/sysmon.md`, `collection/siem-forwarders.md`.

All 11 existing files are deleted once their content has been migrated into the new structure — no content is kept without being absorbed somewhere, and no old files are left alongside the new structure once migration is complete.

## Out of scope for this design (future work)

- PowerShell tool that consumes `settings/subcategories/*.csv` (via `auditpol /restore`) and `settings/registry-settings.csv` to apply audit configuration to a target system, and/or imports from existing GPOs.
- Any tooling to auto-generate `event-catalog/full-table.md` or per-role event tables from `events.json` (could be a simple script, but is not designed here).
