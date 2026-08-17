# Windows Advanced Auditing Guide Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the 11 flat, duplicative markdown files in this repo into a single-source-of-truth event catalog, structured (auditpol-restorable) audit settings data, unified role guides, and a set of collection-strategy docs, per the approved design spec.

**Architecture:** A JSON event catalog (`event-catalog/events.json`) and CSV settings data (`settings/`) become the source of truth; role guides and generated views read from them instead of duplicating data. Collection strategy is split into WEF, SIEM-forwarder, and Sysmon (bridge-only) docs. All content is hand-authored markdown/JSON/CSV — no build scripts are introduced in this phase.

**Tech Stack:** Markdown, JSON, CSV. No external dependencies, no build tooling. Validation uses only tools already on the machine (`python3`, `grep`, standard POSIX utilities).

**Reference spec:** `docs/superpowers/specs/2026-08-16-guide-redesign-design.md`

## Global Constraints

- Target Windows versions: Server 2016+ and Windows 10/11. Note version-introduced field differences only where they matter — do not attempt exhaustive legacy-version coverage.
- No PowerShell tooling in this phase. `settings/` data must be structured so a future tool can consume it directly, but no such tool is built here.
- Audit subcategory CSVs (`settings/subcategories/*.csv`) must use real, Microsoft-documented subcategory GUIDs. Never invent or guess a GUID — if a value can't be confirmed from an authoritative source, leave it as `UNVERIFIED-<subcategory-name>` and flag it in the task's completion notes rather than writing a fabricated value.
- Registry paths/value names in `settings/registry-settings.csv` must be verified against Microsoft documentation (not assumed from memory) for the same reason.
- No new Sysmon deployment/configuration content anywhere in this repo. `collection/sysmon.md` only bridges to `https://github.com/trustedsec/SysmonCommunityGuide` — do not describe install steps, config XML, or per-event Sysmon detail here.
- `event-catalog/full-table.md` is hand-authored to mirror `events.json` — it is explicitly not produced by a script (out of scope per spec).
- The 11 existing root-level files are only deleted in the final task, after every piece of their content has a confirmed new home.
- File/folder naming: lowercase with hyphens (matches the structure already specified in the spec), e.g. `domain-controller.md`, `workstation-baseline.csv`.

---

## File Structure

```
/README.md
/event-catalog/
    events.json
    full-table.md
/settings/
    README.md
    registry-settings.csv
    subcategories/
        workstation-baseline.csv
        workstation-advanced.csv
        server-baseline.csv
        server-advanced.csv
        domain-controller-baseline.csv
        domain-controller-advanced.csv
        certificate-authority-baseline.csv
        certificate-authority-advanced.csv
/guides/
    workstation.md
    server-baseline.md
    domain-controller.md
    certificate-authority.md
/collection/
    xpath-queries.md
    windows-event-forwarding.md
    siem-forwarders.md
    sysmon.md
```

Source files being migrated (all in repo root, read in full during brainstorming — do not re-derive their content, just re-read them directly when doing each task):
- `Master Windows Event ID Reference Table.md`
- `Windows Workstation Event ID Collection Guide.md`
- `Windows Workstation Security Event Logging GPO Configuration Guide.md`
- `Windows Server Baseline Event ID Collection Guide.md`
- `Windows Server Baseline Security Event Logging GPO Configuration Guide.md`
- `Domain Controller Event ID Collection Guide.md`
- `Active Directory Certificate Authority Event ID Collection Guide.md`
- `Certificate Authority Server Security Event Logging GPO Configuration Guide.md`
- `Group Policy Audit Settings Configuration Guide.md`
- `XPath Queries for Windows Event Collection Domain Controllers.md`
- `XPath Query Collection for Windows Event Collection.md`

---

### Task 1: Build the event catalog (`event-catalog/events.json`)

**Files:**
- Create: `event-catalog/events.json`
- Read (do not modify): `Master Windows Event ID Reference Table.md`, `Windows Workstation Event ID Collection Guide.md`, `Windows Server Baseline Event ID Collection Guide.md`, `Domain Controller Event ID Collection Guide.md`, `Active Directory Certificate Authority Event ID Collection Guide.md`

**Interfaces:**
- Produces: `event-catalog/events.json` — a JSON array of objects, each matching this exact shape (consumed by Tasks 2, 3, 8, 9, 10, 11):
  ```json
  {
    "eventId": 4688,
    "logSource": "Security",
    "description": "Process creation",
    "criticality": "High",
    "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "applicableRoles": ["workstation", "server", "domain-controller", "certificate-authority"],
    "requiredSubcategory": "",
    "schema": null
  }
  ```
  - `applicableRoles` values are restricted to exactly: `"workstation"`, `"server"`, `"domain-controller"`, `"certificate-authority"`.
  - `mitre` is always an array (possibly with more than one entry, e.g. event 4648 has both T1078 and T1550.002 in the DC guide — merge these, don't drop either).
  - `schema` is `null` for every record in this task; Task 2 populates it for a subset.

- [ ] **Step 1: Merge all five source files into one deduplicated event list**

  Read each of the five source files listed above. Build one merged list keyed by `eventId` (same event ID appearing in multiple files, e.g. 4624 appears in the Master table, Workstation guide, Server guide, and DC guide, is ONE record).

  For each unique event ID:
  - `logSource`: take from the Master table if present there, otherwise infer from which section/table it appeared under in the source file (e.g. events under a "PowerShell Events" heading with log path `Microsoft-Windows-PowerShell/Operational` use that as `logSource`; events under "Security Log Events" use `"Security"`; events under "System Events" use `"System"`).
  - `description`: use the Master table's wording where the event appears there; otherwise use the wording from whichever guide it came from.
  - `criticality`: if the same event has different criticality across files (this happens — e.g. 4740 is "High" in the Master table but check each source), prefer the **higher** criticality value (High > Medium > Low).
  - `mitre`: union of all MITRE entries seen for that event ID across all source files, deduplicated by technique ID. Parse the MITRE column format `T1234 - Technique Name` (and `T1234.005 - Sub-technique Name`) into `{"id": "T1234", "name": "Technique Name"}` objects.
  - `applicableRoles`: determine from which source guide(s) the event appears in — e.g. an event in both `Windows Workstation Event ID Collection Guide.md` and `Windows Server Baseline Event ID Collection Guide.md` gets `["workstation", "server"]`. An event that appears in the Master table with `Applicable To` = "All" gets `["workstation", "server", "domain-controller", "certificate-authority"]`. An event only in the CA guide gets `["certificate-authority"]` only (note: the CA guide's own `applicableRoles` isn't listed in the file structure section above as a fifth source — read `Active Directory Certificate Authority Event ID Collection Guide.md` directly for its event list even though it wasn't in the five bullet list; it's needed to correctly scope CA-only events like 4868–4898 and the `Microsoft-Windows-CertificationAuthority` events 3–40).
  - `requiredSubcategory`: leave as an empty string `""` for every record. This field is reserved for a future pass that maps each event to its governing `auditpol` subcategory using Microsoft's authoritative event-to-subcategory reference — no task in this plan populates it, and no role guide displays it. Do not attempt to fill it in from memory or inference.
  - `schema`: `null`.

  Write the result as a JSON array to `event-catalog/events.json`, pretty-printed with 2-space indentation, sorted ascending by `eventId`.

- [ ] **Step 2: Validate JSON syntax**

  Run: `python3 -m json.tool event-catalog/events.json > /dev/null && echo VALID`
  Expected: `VALID`

- [ ] **Step 3: Validate record shape and count**

  Run:
  ```bash
  python3 -c "
  import json
  data = json.load(open('event-catalog/events.json'))
  required = {'eventId','logSource','description','criticality','mitre','applicableRoles','requiredSubcategory','schema'}
  valid_roles = {'workstation','server','domain-controller','certificate-authority'}
  ids = [d['eventId'] for d in data]
  assert len(ids) == len(set(ids)), 'duplicate eventId found'
  for d in data:
      assert required.issubset(d.keys()), f'{d.get(\"eventId\")} missing fields'
      assert d['criticality'] in ('High','Medium','Low'), f'{d[\"eventId\"]} bad criticality'
      assert isinstance(d['mitre'], list), f'{d[\"eventId\"]} mitre not a list'
      assert set(d['applicableRoles']).issubset(valid_roles), f'{d[\"eventId\"]} bad role'
  print(f'{len(data)} unique events, all valid')
  "
  ```
  Expected: prints a count with no assertion errors. The count should be roughly 90-110 (the five source files have real overlap; expect meaningfully fewer unique IDs than the sum of all rows across files).

- [ ] **Step 4: Commit**

  ```bash
  git add event-catalog/events.json
  git commit -m "Add merged event catalog as single source of truth"
  ```

---

### Task 2: Add field-level schema to the curated critical event subset

**Files:**
- Modify: `event-catalog/events.json`

**Interfaces:**
- Consumes: `event-catalog/events.json` produced by Task 1.
- Produces: the same file, with `schema` populated (non-null) for exactly these 22 event IDs — this exact list is the "curated critical subset" referenced throughout the guide, do not add or remove IDs from it without updating this plan:
  ```
  4624, 4625, 4634, 4648, 4663, 4670, 4672, 4688, 4698, 4719,
  4720, 4724, 4728, 4732, 4738, 4740, 4768, 4769, 4771, 4776,
  5140, 1102
  ```
  Populated `schema` shape (consumed by Tasks 8-11 when rendering per-role event tables):
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

- [ ] **Step 1: Fetch schema detail for each of the 22 events**

  For each event ID in the list above, fetch its Microsoft Learn event-reference page. These follow the pattern:
  `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-<id>`
  (e.g. `.../event-4688` for event 4688). Use WebFetch on each URL.

  From each page, extract:
  - The minimum Windows version the event's current field set applies to (pages typically note this, e.g. "This event is generated on Windows Server 2016..." or similar — if no version note is present, use `"Windows 10 / Server 2016"` as the default per this guide's version scope).
  - The field table (usually under a "Field Descriptions" or similar heading) — capture each field's exact name and its description, condensed to one sentence.

  If a page is unreachable or restructured such that fields can't be confidently extracted, do not fabricate field data — instead set that event's `schema` to `null` (same as an uncurated event) and note the event ID in your Task completion notes so it can be revisited.

- [ ] **Step 2: Update events.json with the extracted schema data**

  For each of the 22 event IDs, set its `schema` object as described in the Interfaces section above, using the fields extracted in Step 1.

- [ ] **Step 3: Validate JSON syntax and schema coverage**

  Run: `python3 -m json.tool event-catalog/events.json > /dev/null && echo VALID`
  Expected: `VALID`

  Run:
  ```bash
  python3 -c "
  import json
  data = json.load(open('event-catalog/events.json'))
  target = {4624,4625,4634,4648,4663,4670,4672,4688,4698,4719,4720,4724,4728,4732,4738,4740,4768,4769,4771,4776,5140,1102}
  by_id = {d['eventId']: d for d in data}
  missing = [i for i in target if by_id.get(i, {}).get('schema') is None]
  print('events still missing schema (expected empty unless a page was unreachable):', missing)
  for i in target:
      if i in by_id and by_id[i]['schema'] is not None:
          assert 'fields' in by_id[i]['schema'] and len(by_id[i]['schema']['fields']) > 0, f'{i} has empty fields'
  print('OK')
  "
  ```
  Expected: `OK`, with `missing` ideally empty (non-empty is acceptable only if noted per Step 1's fallback).

- [ ] **Step 4: Commit**

  ```bash
  git add event-catalog/events.json
  git commit -m "Add field-level schema for curated critical event subset"
  ```

---

### Task 3: Author `event-catalog/full-table.md`

**Files:**
- Create: `event-catalog/full-table.md`
- Read (do not modify): `event-catalog/events.json`

**Interfaces:**
- Consumes: `event-catalog/events.json` (final form, from Tasks 1-2).
- Produces: `event-catalog/full-table.md`, referenced from the top-level README (Task 16).

- [ ] **Step 1: Hand-author the flat table**

  Write `event-catalog/full-table.md` with this structure:
  ```markdown
  # Full Event ID Catalog

  Generated view of `events.json` — the source of truth. Do not edit this file's table
  independently of `events.json`; update the JSON and re-sync this table instead.

  | Event ID | Log Source | Description | Criticality | MITRE Technique(s) | Applicable Roles | Schema Available |
  |----------|-----------|-------------|-------------|---------------------|-------------------|-------------------|
  | 4688 | Security | Process creation | High | T1059 - Command and Scripting Interpreter | workstation, server, domain-controller, certificate-authority | Yes |
  ```
  One row per record in `events.json`, sorted ascending by `eventId`. `MITRE Technique(s)` joins multiple entries with `; `. `Schema Available` is `"Yes"` if that record's `schema` is non-null, else `"No"`.

  Add a short legend below the table explaining the `Applicable Roles` values and pointing to `guides/<role>.md` for the narrative version of each role's subset, and to the per-event schema (say: "events marked Schema Available = Yes have full field documentation in `events.json`; a future pass may render these inline here").

- [ ] **Step 2: Verify every event ID from events.json appears in the table**

  Run:
  ```bash
  python3 -c "
  import json, re
  data = json.load(open('event-catalog/events.json'))
  ids = {str(d['eventId']) for d in data}
  table = open('event-catalog/full-table.md').read()
  found = set(re.findall(r'^\| (\d+) \|', table, re.MULTILINE))
  missing = ids - found
  extra = found - ids
  assert not missing, f'missing from table: {missing}'
  assert not extra, f'in table but not in events.json: {extra}'
  print(f'{len(found)} rows match events.json exactly')
  "
  ```
  Expected: prints a match count, no assertion errors.

- [ ] **Step 3: Commit**

  ```bash
  git add event-catalog/full-table.md
  git commit -m "Add generated full event table view"
  ```

---

### Task 4: Build `settings/subcategories/` CSVs for workstation and server

**Files:**
- Create: `settings/subcategories/workstation-baseline.csv`
- Create: `settings/subcategories/workstation-advanced.csv`
- Create: `settings/subcategories/server-baseline.csv`
- Create: `settings/subcategories/server-advanced.csv`
- Read (do not modify): `Group Policy Audit Settings Configuration Guide.md`

**Interfaces:**
- Produces: four CSVs, each shaped exactly like `auditpol /backup /file:X.csv` output, header row (consumed by Tasks 8, 9 for linking, and by the future PowerShell tool — not built in this phase):
  ```
  Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
  ```
  `Setting Value` encoding (this is the field `auditpol /restore` actually applies): `0` = No Auditing, `1` = Success, `2` = Failure, `3` = Success and Failure. `Machine Name` is left blank (auditpol ignores it on restore). `Policy Target` is always `System`. `Exclusion Setting` is left blank for all rows in this guide (we don't use exclusion policies).

- [ ] **Step 1: Look up authoritative subcategory GUIDs**

  Use WebFetch on `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings` (Microsoft's Advanced Security Audit Policy Settings reference). This page documents each of the ~60 audit subcategories; cross-reference against it (or an equivalently authoritative Microsoft source if that URL has moved) to build a Subcategory Name → GUID lookup table covering every subcategory named in `Group Policy Audit Settings Configuration Guide.md`.

  Per the Global Constraints: if a subcategory's GUID cannot be confirmed from an authoritative source, write `UNVERIFIED-<subcategory-name>` in the Subcategory GUID column for that row instead of guessing, and list it in your Task completion notes.

- [ ] **Step 2: Define the Baseline and Advanced subcategory sets**

  From `Group Policy Audit Settings Configuration Guide.md`'s "Advanced Audit Policy Configuration" section, split subcategories into two tiers:

  **Baseline** (minimum viable — low volume, highest-signal): Audit Credential Validation, Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations, Audit Computer Account Management, Audit Security Group Management, Audit User Account Management, Audit Process Creation, Audit Account Lockout, Audit Logoff, Audit Logon, Audit Special Logon, Audit Audit Policy Change, Audit Sensitive Privilege Use, Audit Security State Change, Audit Security System Extension, Audit System Integrity.

  **Advanced** (Baseline plus): Audit Other Account Management Events, Audit DPAPI Activity, Audit File System, Audit Handle Manipulation, Audit Registry, Audit Kernel Object, Audit File Share, Audit Detailed File Share, Audit Authentication Policy Change, Audit MPSSVC Rule-Level Policy Change, Audit Other Policy Change Events, Audit Other Logon/Logoff Events.

  (`DS Access` subcategories — Audit Directory Service Access, Audit Directory Service Changes — are domain-controller-only and are handled in Task 5, not here.)

  Success/Failure inclusion per subcategory matches `Group Policy Audit Settings Configuration Guide.md`'s existing recommendations (nearly all are "Success and Failure"; note the two exceptions called out there: Audit Process Creation is Success-only, Audit Logoff is Success-only, Audit Special Logon is Success-only).

- [ ] **Step 3: Write the four CSV files**

  `workstation-baseline.csv` and `server-baseline.csv` both get the Baseline subcategory set (identical content for this pass — workstation and server share the same subcategory-level recommendations per the source guide; role-specific differences live in the registry settings and narrative, not here). `workstation-advanced.csv` and `server-advanced.csv` get Baseline + Advanced combined.

  Each row: `,System,<Subcategory Name>,<GUID>,<Success and Failure|Success|Failure>,,<0-3>`

  Example row from `workstation-baseline.csv`:
  ```
  ,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
  ```

- [ ] **Step 4: Validate CSV structure**

  Run for each of the four files (example shown for one):
  ```bash
  python3 -c "
  import csv
  with open('settings/subcategories/workstation-baseline.csv') as f:
      rows = list(csv.reader(f))
  assert rows[0] == ['Machine Name','Policy Target','Subcategory','Subcategory GUID','Inclusion Setting','Exclusion Setting','Setting Value']
  for r in rows[1:]:
      assert r[1] == 'System', r
      assert r[6] in ('0','1','2','3'), r
  print(f'{len(rows)-1} valid rows')
  "
  ```
  Expected: prints a row count, no assertion errors. Repeat for `workstation-advanced.csv`, `server-baseline.csv`, `server-advanced.csv`.

- [ ] **Step 5: Commit**

  ```bash
  git add settings/subcategories/workstation-baseline.csv settings/subcategories/workstation-advanced.csv settings/subcategories/server-baseline.csv settings/subcategories/server-advanced.csv
  git commit -m "Add auditpol-restorable subcategory CSVs for workstation and server"
  ```

---

### Task 5: Build `settings/subcategories/` CSVs for domain-controller and certificate-authority

**Files:**
- Create: `settings/subcategories/domain-controller-baseline.csv`
- Create: `settings/subcategories/domain-controller-advanced.csv`
- Create: `settings/subcategories/certificate-authority-baseline.csv`
- Create: `settings/subcategories/certificate-authority-advanced.csv`
- Read (do not modify): `Group Policy Audit Settings Configuration Guide.md`

**Interfaces:**
- Consumes: same GUID lookup approach as Task 4, Step 1 (redo the WebFetch lookup for `DS Access` subcategories specifically — Task 4 doesn't cover those).
- Produces: same CSV shape as Task 4.

- [ ] **Step 1: Look up GUIDs for DS Access subcategories**

  Use the same WebFetch source as Task 4 Step 1 to confirm GUIDs for: Audit Directory Service Access, Audit Directory Service Changes. Same fallback rule applies if unconfirmed (`UNVERIFIED-<name>`).

- [ ] **Step 2: Write domain-controller CSVs**

  `domain-controller-baseline.csv` = the workstation/server Baseline set from Task 4 Step 2, **plus** Audit Directory Service Access and Audit Directory Service Changes (both Success and Failure).

  `domain-controller-advanced.csv` = Baseline + the workstation/server Advanced set from Task 4 Step 2 (DS Access subcategories are already included via Baseline).

- [ ] **Step 3: Write certificate-authority CSVs**

  `certificate-authority-baseline.csv` = the workstation/server Baseline set from Task 4 Step 2 (CA servers still need core logon/account/process auditing).

  `certificate-authority-advanced.csv` = Baseline + the workstation/server Advanced set from Task 4 Step 2. (CA-specific certificate-services auditing is controlled by CA-level audit filters, not `auditpol` subcategories — that's covered narratively in `guides/certificate-authority.md`, Task 11, not in these CSVs.)

- [ ] **Step 4: Validate CSV structure**

  Run the same validation script pattern as Task 4 Step 4 against all four new files, adjusted for `assert len(rows)-1 >= 16` (baseline files) and `>= 28` (advanced files, since DC/CA advanced should have at least as many rows as workstation/server advanced) to sanity-check nothing was accidentally dropped.

- [ ] **Step 5: Commit**

  ```bash
  git add settings/subcategories/domain-controller-baseline.csv settings/subcategories/domain-controller-advanced.csv settings/subcategories/certificate-authority-baseline.csv settings/subcategories/certificate-authority-advanced.csv
  git commit -m "Add auditpol-restorable subcategory CSVs for domain controller and CA"
  ```

---

### Task 6: Build `settings/registry-settings.csv`

**Files:**
- Create: `settings/registry-settings.csv`
- Read (do not modify): `Group Policy Audit Settings Configuration Guide.md`

**Interfaces:**
- Produces: `settings/registry-settings.csv`, columns exactly: `Role,Tier,Hive,KeyPath,ValueName,Type,Data,Description` (consumed narratively by Tasks 8-11, and by the future PowerShell tool — not built in this phase). `Role` values: `all` (applies to every role) or one of `workstation`, `server`, `domain-controller`, `certificate-authority`. `Tier`: `baseline` or `advanced`.

- [ ] **Step 1: Verify each registry path against Microsoft documentation**

  For each Administrative Templates setting in `Group Policy Audit Settings Configuration Guide.md`'s "Administrative Templates Settings" section (PowerShell Module/Script Block/Transcription logging, Process Creation command-line inclusion, Force audit policy subcategory override, Event Log max size/retention for Application/Security/System), use WebFetch against Microsoft's Group Policy / PowerShell auditing documentation (e.g. `about_Logging_Windows` PowerShell docs for the PowerShell keys, and the Windows Event Log admx registry reference for the log-size keys) to confirm the exact registry hive, key path, value name, and value type. Do not write a row from memory alone — confirm it, per the Global Constraints GUID/registry caution.

- [ ] **Step 2: Write the CSV rows**

  One row per setting, e.g.:
  ```
  Role,Tier,Hive,KeyPath,ValueName,Type,Data,Description
  all,baseline,HKLM,SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging,EnableScriptBlockLogging,REG_DWORD,1,Enable PowerShell Script Block Logging
  ```
  Cover: PowerShell Module Logging (including the `ModuleNames = *` wildcard entry — note in the `Description` that this is a subkey value, not a top-level value, if that's what Step 1 confirms), PowerShell Script Block Logging, PowerShell Transcription (mark `Tier=advanced`, optional per the source guide), Process Creation command-line inclusion, Force audit policy subcategory override (`SCENoApplyLegacyAuditPolicy` or whatever Step 1 confirms), and Event Log MaxSize + Retention for each of Application, Security, System (6 rows total for these).

- [ ] **Step 3: Validate CSV structure**

  Run:
  ```bash
  python3 -c "
  import csv
  with open('settings/registry-settings.csv') as f:
      rows = list(csv.reader(f))
  assert rows[0] == ['Role','Tier','Hive','KeyPath','ValueName','Type','Data','Description']
  valid_roles = {'all','workstation','server','domain-controller','certificate-authority'}
  for r in rows[1:]:
      assert r[0] in valid_roles, r
      assert r[1] in ('baseline','advanced'), r
      assert r[2] == 'HKLM', r
  print(f'{len(rows)-1} valid rows')
  "
  ```
  Expected: prints a row count (roughly 10-12), no assertion errors.

- [ ] **Step 4: Commit**

  ```bash
  git add settings/registry-settings.csv
  git commit -m "Add registry-based Administrative Templates settings data"
  ```

---

### Task 7: Write `settings/README.md`

**Files:**
- Create: `settings/README.md`
- Read (do not modify): `settings/subcategories/*.csv` (all 8), `settings/registry-settings.csv`

**Interfaces:**
- Consumes: file names/paths from Tasks 4-6 (link targets).
- Produces: `settings/README.md`, linked from the top-level README (Task 16) and each role guide (Tasks 8-11).

- [ ] **Step 1: Write the explainer doc**

  Content to include, as actual prose (not a placeholder outline):
  - What the two data files are: `subcategories/*.csv` are literal `auditpol /backup`-format files, restorable with `auditpol /restore /file:<path>`; `registry-settings.csv` lists Administrative Templates values not covered by `auditpol`, to be applied via `reg.exe` or `Set-ItemProperty`.
  - A worked example: `auditpol /restore /file:settings\subcategories\workstation-baseline.csv` run from an elevated command prompt on the target machine, and a `reg.exe add` example for one row of `registry-settings.csv`.
  - A note that a PowerShell tool to automate this end-to-end (including GPO import) is planned but not yet built — link to the design spec at `docs/superpowers/specs/2026-08-16-guide-redesign-design.md` for anyone who wants to build it early.
  - A "manual GPMC fallback" section: for teams that prefer to configure this through Group Policy Management Console directly instead of `auditpol`/registry scripting, point to `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration` and `Computer Configuration -> Policies -> Administrative Templates`, and note that the CSV/registry data above is the authoritative list of *what* to set — GPMC is just an alternate *how*.
  - A table listing all 8 subcategory CSVs and `registry-settings.csv` with one-line descriptions and relative links.

- [ ] **Step 2: Verify all links resolve**

  Run:
  ```bash
  grep -oE '\]\(([^)]+)\)' settings/README.md | sed -E 's/\]\(//;s/\)$//' | while read -r link; do
    case "$link" in
      http*) continue ;;
      *) [ -f "settings/$link" ] || [ -f "$link" ] && echo "OK: $link" || echo "BROKEN: $link" ;;
    esac
  done
  ```
  Expected: no `BROKEN` lines.

- [ ] **Step 3: Commit**

  ```bash
  git add settings/README.md
  git commit -m "Add settings directory explainer"
  ```

---

### Task 8: Write `guides/workstation.md`

**Files:**
- Create: `guides/workstation.md`
- Read (do not modify): `event-catalog/events.json`, `settings/subcategories/workstation-baseline.csv`, `settings/subcategories/workstation-advanced.csv`, `settings/registry-settings.csv`, `Windows Workstation Event ID Collection Guide.md`, `Windows Workstation Security Event Logging GPO Configuration Guide.md`

**Interfaces:**
- Consumes: `events.json` schema from Task 1/2, CSV files from Task 4, registry CSV from Task 6.
- Produces: `guides/workstation.md`, linked from top-level README (Task 16).

- [ ] **Step 1: Write the guide following the unified template**

  Sections, in order:
  1. **Scope** — one paragraph on what "workstation" covers here (end-user Windows 10/11 machines) and why they matter (largest attack surface, often least monitored).
  2. **Baseline settings** — narrative summary of what's in `settings/subcategories/workstation-baseline.csv` (pull the subcategory names from that file — don't re-invent the list) plus the `Role=all|workstation, Tier=baseline` rows from `settings/registry-settings.csv`, with a relative link to both files.
  3. **Advanced settings** — same pattern for `workstation-advanced.csv` and `Tier=advanced` registry rows, framed as "beyond baseline, add:".
  4. **Event table** — a markdown table of every event in `event-catalog/events.json` where `applicableRoles` includes `"workstation"`, columns: Event ID, Log Source, Description, Criticality, MITRE Technique(s). Sort ascending by Event ID.
  5. **Role-specific notes** — carry forward the workstation-specific operational notes from `Windows Workstation Event ID Collection Guide.md`'s "Key Monitoring Scenarios" and "Recommended Additional Monitoring" sections (condense, don't just copy verbatim if redundant with the event table above).

- [ ] **Step 2: Verify the event table matches events.json**

  Run:
  ```bash
  python3 -c "
  import json, re
  data = json.load(open('event-catalog/events.json'))
  expected = {str(d['eventId']) for d in data if 'workstation' in d['applicableRoles']}
  table = open('guides/workstation.md').read()
  found = set(re.findall(r'^\| (\d+) \|', table, re.MULTILINE))
  missing = expected - found
  assert not missing, f'missing from workstation guide table: {missing}'
  print(f'{len(found)} workstation events present')
  "
  ```
  Expected: prints a count, no assertion errors.

- [ ] **Step 3: Commit**

  ```bash
  git add guides/workstation.md
  git commit -m "Add unified workstation role guide"
  ```

---

### Task 9: Write `guides/server-baseline.md`

**Files:**
- Create: `guides/server-baseline.md`
- Read (do not modify): `event-catalog/events.json`, `settings/subcategories/server-baseline.csv`, `settings/subcategories/server-advanced.csv`, `settings/registry-settings.csv`, `Windows Server Baseline Event ID Collection Guide.md`, `Windows Server Baseline Security Event Logging GPO Configuration Guide.md`

**Interfaces:**
- Same pattern as Task 8, scoped to `"server"` role.

- [ ] **Step 1: Write the guide following the unified template**

  Same five sections as Task 8 Step 1, scoped to general Windows Server (non-DC, non-CA) member servers, sourced from `server-baseline.csv`/`server-advanced.csv`/`registry-settings.csv` and role-specific notes from `Windows Server Baseline Event ID Collection Guide.md`'s "Key Monitoring Scenarios", "Required Audit Policies", and "Important Log Sources" sections.

- [ ] **Step 2: Verify the event table matches events.json**

  Same verification pattern as Task 8 Step 2, filtered on `'server' in d['applicableRoles']` and checked against `guides/server-baseline.md`.

- [ ] **Step 3: Commit**

  ```bash
  git add guides/server-baseline.md
  git commit -m "Add unified server baseline role guide"
  ```

---

### Task 10: Write `guides/domain-controller.md`

**Files:**
- Create: `guides/domain-controller.md`
- Read (do not modify): `event-catalog/events.json`, `settings/subcategories/domain-controller-baseline.csv`, `settings/subcategories/domain-controller-advanced.csv`, `settings/registry-settings.csv`, `Domain Controller Event ID Collection Guide.md`

**Interfaces:**
- Same pattern as Task 8, scoped to `"domain-controller"` role.

- [ ] **Step 1: Write the guide following the unified template**

  Same five sections, scoped to Active Directory Domain Controllers, sourced from `domain-controller-baseline.csv`/`domain-controller-advanced.csv`/`registry-settings.csv` and role-specific notes from `Domain Controller Event ID Collection Guide.md`'s "Notes" section. Explicitly call out the Directory Service Access/Changes subcategories as DC-specific in the Baseline settings section (they don't exist for other roles).

- [ ] **Step 2: Verify the event table matches events.json**

  Same verification pattern as Task 8 Step 2, filtered on `'domain-controller' in d['applicableRoles']` and checked against `guides/domain-controller.md`.

- [ ] **Step 3: Commit**

  ```bash
  git add guides/domain-controller.md
  git commit -m "Add unified domain controller role guide"
  ```

---

### Task 11: Write `guides/certificate-authority.md`

**Files:**
- Create: `guides/certificate-authority.md`
- Read (do not modify): `event-catalog/events.json`, `settings/subcategories/certificate-authority-baseline.csv`, `settings/subcategories/certificate-authority-advanced.csv`, `settings/registry-settings.csv`, `Active Directory Certificate Authority Event ID Collection Guide.md`, `Certificate Authority Server Security Event Logging GPO Configuration Guide.md`

**Interfaces:**
- Same pattern as Task 8, scoped to `"certificate-authority"` role.

- [ ] **Step 1: Write the guide following the unified template**

  Same five sections, scoped to AD Certificate Services (CA) servers, sourced from `certificate-authority-baseline.csv`/`certificate-authority-advanced.csv`/`registry-settings.csv`. For CA-specific settings not covered by `auditpol` (the CA's own audit filter, configured via `certutil -setreg CA\AuditFilter` or the CA MMC snap-in's Auditing tab), read `Certificate Authority Server Security Event Logging GPO Configuration Guide.md` for the exact recommended filter value and document it narratively in this section (not in a CSV — it's CA-specific, not a `auditpol`/registry setting, so it stays out of `settings/` per the data model). Role-specific notes come from `Active Directory Certificate Authority Event ID Collection Guide.md`'s "Key Monitoring Scenarios" section.

- [ ] **Step 2: Verify the event table matches events.json**

  Same verification pattern as Task 8 Step 2, filtered on `'certificate-authority' in d['applicableRoles']` and checked against `guides/certificate-authority.md`.

- [ ] **Step 3: Commit**

  ```bash
  git add guides/certificate-authority.md
  git commit -m "Add unified certificate authority role guide"
  ```

---

### Task 12: Write `collection/xpath-queries.md`

**Files:**
- Create: `collection/xpath-queries.md`
- Read (do not modify): `XPath Queries for Windows Event Collection Domain Controllers.md`, `XPath Query Collection for Windows Event Collection.md`

**Interfaces:**
- Produces: `collection/xpath-queries.md`, referenced by `collection/windows-event-forwarding.md` (Task 13).

- [ ] **Step 1: Merge and deduplicate both source files**

  Combine every query from both source files into one document, organized by log source (Security, System, PowerShell, WMI, RDP/Terminal Services, Windows Defender, Certificate Services, Firewall — matching the section structure already used in `XPath Query Collection for Windows Event Collection.md`). Where the same category of query exists in both files with different event ID sets (e.g. one file's Certificate Services query vs the other's), merge the event ID lists into one query, removing duplicates. Keep the "Usage Examples" section (`wevtutil`, `Get-WinEvent`, WEF subscription snippet) and the "Best Practices"/"Notes" sections from `XPath Query Collection for Windows Event Collection.md`, updated to mention the 20-event-ID-per-query Windows limitation still applies.

- [ ] **Step 2: Validate all XML query blocks are well-formed**

  Run:
  ```bash
  python3 -c "
  import re, xml.etree.ElementTree as ET
  content = open('collection/xpath-queries.md').read()
  blocks = re.findall(r'\`\`\`xml\n(.*?)\`\`\`', content, re.DOTALL)
  for i, b in enumerate(blocks):
      ET.fromstring(b)
  print(f'{len(blocks)} XML blocks all well-formed')
  "
  ```
  Expected: prints a count, no parse errors.

- [ ] **Step 3: Commit**

  ```bash
  git add collection/xpath-queries.md
  git commit -m "Consolidate XPath query collections into one document"
  ```

---

### Task 13: Write `collection/windows-event-forwarding.md`

**Files:**
- Create: `collection/windows-event-forwarding.md`
- Read (do not modify): `collection/xpath-queries.md` (from Task 12)

**Interfaces:**
- Consumes: `collection/xpath-queries.md` path (link target).
- Produces: `collection/windows-event-forwarding.md`, linked from top-level README (Task 16).

- [ ] **Step 1: Write the WEF/WEC setup guide**

  Cover, as real prose/steps (not a placeholder outline):
  - What WEF/WEC is and when to use it (native, no agent install, works well when you already have a Windows Event Collector role available).
  - Source-initiated vs collector-initiated subscriptions — what each requires (GPO-pushed subscription config for source-initiated; explicit target list for collector-initiated) and when to pick each (source-initiated scales better for large/dynamic fleets).
  - Setting up the Windows Event Collector role (`wecutil qc`), configuring the source computers' `Network Service` read access to the Security log (`wevtutil sl Security /ca:...`), and the GPO settings needed on source machines (`Configure target Subscription Manager` under Computer Configuration -> Administrative Templates -> Windows Components -> Event Forwarding).
  - Kerberos vs HTTPS/certificate-based transport — when each is required (Kerberos works within a single AD forest; HTTPS/certs needed cross-forest or for non-domain-joined sources).
  - How to build a subscription using the queries in `collection/xpath-queries.md` (link to it), with one worked example subscription XML using one of that file's queries.
  - Basic troubleshooting pointers (checking `Microsoft-Windows-Eventlog-ForwardingPlugin/Operational` and `Microsoft-Windows-Forwarding/Operational` on collector/source respectively).

- [ ] **Step 2: Verify the link to xpath-queries.md resolves**

  Run: `grep -q 'xpath-queries.md' collection/windows-event-forwarding.md && test -f collection/xpath-queries.md && echo OK`
  Expected: `OK`

- [ ] **Step 3: Commit**

  ```bash
  git add collection/windows-event-forwarding.md
  git commit -m "Add Windows Event Forwarding collection strategy guide"
  ```

---

### Task 14: Write `collection/siem-forwarders.md`

**Files:**
- Create: `collection/siem-forwarders.md`

**Interfaces:**
- Produces: `collection/siem-forwarders.md`, linked from top-level README (Task 16).

- [ ] **Step 1: Write the agent-based forwarding guide**

  Cover, as real prose (not a placeholder outline):
  - When to choose an agent over WEF: you already run a SIEM/EDR with its own forwarder, need enrichment/parsing at the edge, or need multi-destination fan-out.
  - Three options with a short paragraph each on install/config basics and where to go for full docs (link out, don't reproduce vendor docs):
    - **Winlogbeat** — Elastic's lightweight forwarder; config via `winlogbeat.yml` event_logs list; link to Elastic's official Winlogbeat docs.
    - **Splunk Universal Forwarder** — deployed via `inputs.conf` WinEventLog stanzas; link to Splunk's official UF docs.
    - **Azure Monitor Agent (AMA)** — for Sentinel/Log Analytics destinations, configured via Data Collection Rules rather than local config files; link to Microsoft's AMA docs.
  - A short decision note: agent-based forwarding duplicates what WEF already does for free within a single AD environment — the main reason to add an agent is a destination WEF can't reach natively (a cloud SIEM) or enrichment you can't get from raw XML.

- [ ] **Step 2: Verify no broken internal links**

  Run: `grep -oE '\]\(([^)h][^)]*)\)' collection/siem-forwarders.md` (this surfaces any non-`http` links) and manually confirm each resolves, or confirm there are none (expected, since this doc primarily links externally).

- [ ] **Step 3: Commit**

  ```bash
  git add collection/siem-forwarders.md
  git commit -m "Add SIEM agent forwarder collection strategy guide"
  ```

---

### Task 15: Write `collection/sysmon.md`

**Files:**
- Create: `collection/sysmon.md`

**Interfaces:**
- Produces: `collection/sysmon.md`, linked from top-level README (Task 16).

- [ ] **Step 1: Write the short bridge doc**

  Per the Global Constraints, this must NOT include install steps, config XML, or per-event Sysmon detail. Content:
  - One paragraph: why Sysmon complements native Windows Security auditing — it covers gaps native auditing doesn't reach (network connections, image/DLL loads, raw disk access, DNS queries, named pipe creation, process access with granular masks) that no amount of `auditpol` tuning provides.
  - One paragraph: how Sysmon fits into this guide's collection pipeline — its output lands in the `Microsoft-Windows-Sysmon/Operational` log, which is collected the same way as everything else in this guide (via WEF, see `collection/windows-event-forwarding.md`, or an agent, see `collection/siem-forwarders.md`) — no separate collection mechanism needed.
  - A clear link-out: "For installation, configuration, and event-by-event reference, see the [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) — this repo doesn't duplicate that content."

- [ ] **Step 2: Verify the link is present and correctly formed**

  Run: `grep -q 'https://github.com/trustedsec/SysmonCommunityGuide' collection/sysmon.md && echo OK`
  Expected: `OK`

- [ ] **Step 3: Commit**

  ```bash
  git add collection/sysmon.md
  git commit -m "Add Sysmon collection bridge doc"
  ```

---

### Task 16: Write top-level `README.md`

**Files:**
- Create: `README.md`
- Read (do not modify): `event-catalog/full-table.md`, `settings/README.md`, `guides/*.md` (all 4), `collection/*.md` (all 4)

**Interfaces:**
- Consumes: every file path created in Tasks 1-15 (link targets).
- Produces: `README.md` — the guide's entry point.

- [ ] **Step 1: Write the README**

  Content:
  - One paragraph: what this guide is, who it's for (SOC analysts and sysadmins), and the motivating problem (most environments seen in IR engagements lack basic Windows auditing).
  - A "Quickstart" section: for a team starting from zero, the fastest path is: pick your role guide (`guides/workstation.md`, `guides/server-baseline.md`, `guides/domain-controller.md`, `guides/certificate-authority.md`), apply its Baseline settings (`settings/README.md` explains how), set up collection (`collection/windows-event-forwarding.md` for the native path).
  - A navigation table listing every doc in the repo (event catalog, settings, guides, collection) with a one-line description and relative link.
  - A "Status" note: audit settings and event data are current as of this guide's last update; a planned PowerShell tool to automate applying these settings is not yet built (link to the design spec).

- [ ] **Step 2: Verify every linked file exists**

  Run:
  ```bash
  grep -oE '\]\(([^)]+)\)' README.md | sed -E 's/\]\(//;s/\)$//' | while read -r link; do
    case "$link" in
      http*) continue ;;
      *) if [ -f "$link" ]; then echo "OK: $link"; else echo "BROKEN: $link"; fi ;;
    esac
  done
  ```
  Expected: no `BROKEN` lines.

- [ ] **Step 3: Commit**

  ```bash
  git add README.md
  git commit -m "Add top-level README as guide entry point"
  ```

---

### Task 17: Delete migrated files and run final verification

**Files:**
- Delete: `Master Windows Event ID Reference Table.md`, `Windows Workstation Event ID Collection Guide.md`, `Windows Workstation Security Event Logging GPO Configuration Guide.md`, `Windows Server Baseline Event ID Collection Guide.md`, `Windows Server Baseline Security Event Logging GPO Configuration Guide.md`, `Domain Controller Event ID Collection Guide.md`, `Active Directory Certificate Authority Event ID Collection Guide.md`, `Certificate Authority Server Security Event Logging GPO Configuration Guide.md`, `Group Policy Audit Settings Configuration Guide.md`, `XPath Queries for Windows Event Collection Domain Controllers.md`, `XPath Query Collection for Windows Event Collection.md`

**Interfaces:**
- Consumes: confirmation that Tasks 1-16 are all committed (this task must run last).

- [ ] **Step 1: Confirm no remaining references to the old files**

  Run:
  ```bash
  for f in "Master Windows Event ID Reference Table.md" "Windows Workstation Event ID Collection Guide.md" "Windows Workstation Security Event Logging GPO Configuration Guide.md" "Windows Server Baseline Event ID Collection Guide.md" "Windows Server Baseline Security Event Logging GPO Configuration Guide.md" "Domain Controller Event ID Collection Guide.md" "Active Directory Certificate Authority Event ID Collection Guide.md" "Certificate Authority Server Security Event Logging GPO Configuration Guide.md" "Group Policy Audit Settings Configuration Guide.md" "XPath Queries for Windows Event Collection Domain Controllers.md" "XPath Query Collection for Windows Event Collection.md"; do
    grep -rl -- "$f" --include='*.md' . | grep -v "^\./$f$" && echo "REFERENCED: $f"
  done
  echo "check complete"
  ```
  Expected: no `REFERENCED:` lines (any hit means some new doc still points at an old filename and needs fixing before deletion).

- [ ] **Step 2: Delete the old files**

  ```bash
  git rm "Master Windows Event ID Reference Table.md" "Windows Workstation Event ID Collection Guide.md" "Windows Workstation Security Event Logging GPO Configuration Guide.md" "Windows Server Baseline Event ID Collection Guide.md" "Windows Server Baseline Security Event Logging GPO Configuration Guide.md" "Domain Controller Event ID Collection Guide.md" "Active Directory Certificate Authority Event ID Collection Guide.md" "Certificate Authority Server Security Event Logging GPO Configuration Guide.md" "Group Policy Audit Settings Configuration Guide.md" "XPath Queries for Windows Event Collection Domain Controllers.md" "XPath Query Collection for Windows Event Collection.md"
  ```

- [ ] **Step 3: Run full-repo link verification**

  Run:
  ```bash
  find . -name '*.md' -not -path './docs/*' -not -path './.git/*' | while read -r file; do
    dir=$(dirname "$file")
    grep -oE '\]\(([^)]+)\)' "$file" | sed -E 's/\]\(//;s/\)$//' | while read -r link; do
      case "$link" in
        http*|"#"*) continue ;;
        *) target="$dir/$link"; [ -f "$target" ] || echo "BROKEN in $file: $link" ;;
      esac
    done
  done
  echo "verification complete"
  ```
  Expected: no `BROKEN in` lines.

- [ ] **Step 4: Commit**

  ```bash
  git commit -m "Remove old flat files now fully migrated into new structure"
  ```

---

## Self-Review Notes

- **Spec coverage:** every element of the "Repo structure", "Data model", "Content strategy", and "Migration plan" sections of the design spec maps to a task above (Tasks 1-3 = event catalog; Tasks 4-7 = settings; Tasks 8-11 = role guides; Tasks 12-15 = collection docs; Task 16 = README; Task 17 = migration cleanup).
- **GUID/registry accuracy:** Tasks 4, 5, and 6 explicitly require WebFetch verification against Microsoft sources rather than relying on memory, per the design spec's implicit requirement that the settings data be trustworthy enough for a future PowerShell tool to apply directly.
- **Sysmon boundary:** Task 15 explicitly restates the "no deployment content" constraint inline so it can't be missed even if this task is executed by a fresh subagent with no other context.
- **Ordering:** Tasks 1-3 (event catalog) and 4-7 (settings) have no dependency on each other and could run in parallel; Tasks 8-11 (role guides) depend on both; Tasks 12-15 (collection docs) are independent of 1-11; Task 16 depends on all prior tasks; Task 17 must run last.
- **`requiredSubcategory` deferred:** flagged during the pre-flight conflict scan — Task 1 originally claimed Task 4/5 would populate this field, but neither task writes to `events.json`. Resolved by leaving it `""` for all records in this pass; no task or role guide depends on it being populated.
