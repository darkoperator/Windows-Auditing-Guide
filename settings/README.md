# settings/

This directory holds the machine-readable audit configuration data for the guide. Every setting recommended in the role guides (under `guides/`) traces back to a row in one of the files here. There are two kinds of files, and they are applied with two different tools.

## The two data files

### `subcategories/*.csv` — `auditpol` backup files

The eight CSVs under `subcategories/` are **literal `auditpol /backup`-format files**. They use the exact column layout `auditpol` itself produces:

```
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
```

Because they're in native `auditpol` backup format, they don't need a custom parser or a translation step — Windows already knows how to read them. Each file is restorable directly with:

```
auditpol /restore /file:<path>
```

This is what governs the settings under Advanced Audit Policy Configuration (the `Subcategory` / `Success and Failure` / `Setting Value` audit policy, as opposed to Administrative Templates policy).

### `registry-settings.csv` — Administrative Templates values

[`registry-settings.csv`](registry-settings.csv) lists settings that live under **Administrative Templates** rather than Advanced Audit Policy Configuration, so `auditpol` cannot set them. These are things like PowerShell Module/Script Block Logging, "Include command line in process creation events," and Security/Application/System event log size and retention. Columns:

```
Role,Tier,Hive,KeyPath,ValueName,Type,Data,Description
```

Every current row has `Role = all` (these apply regardless of machine role) and `Tier` of `baseline` or `advanced`, matching the tiering used for the `subcategories/` CSVs. These rows are applied one at a time via `reg.exe` or PowerShell's `Set-ItemProperty`, not `auditpol`.

## Worked example

Run both of the following from an **elevated** (Administrator) command prompt on the target machine.

**1. Restore an `auditpol` subcategory file** — e.g. apply the workstation baseline:

```
auditpol /restore /file:settings\subcategories\workstation-baseline.csv
```

**2. Apply a registry-settings.csv row with `reg.exe`** — e.g. the row that enables PowerShell Script Block Logging (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, value `EnableScriptBlockLogging`, `REG_DWORD`, data `1`):

```
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

The equivalent in PowerShell, using `Set-ItemProperty` (creating the key first if it doesn't exist):

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1
```

Repeat step 2 for each row of `registry-settings.csv` that applies to the tier you're deploying (`baseline` and/or `advanced`).

## A PowerShell tool is planned, not built yet

Applying every row of `registry-settings.csv` by hand doesn't scale. A future PowerShell tool is planned to automate this end-to-end — restoring the right `subcategories/*.csv` file, walking `registry-settings.csv` and applying each row, and optionally importing the result into a GPO — but **it does not exist yet**. The data files in this directory were deliberately structured (native `auditpol` backup format, flat CSV with explicit `Role`/`Tier` columns) so that tool can consume them directly without a translation layer. See the design spec for the intended shape of that tool if you want to build it early:

[`docs/superpowers/specs/2026-08-16-guide-redesign-design.md`](../docs/superpowers/specs/2026-08-16-guide-redesign-design.md)

Until that tool exists, use the manual steps above (or the GPMC fallback below).

## Manual GPMC fallback

Some teams prefer to configure these settings through Group Policy Management Console (GPMC) directly, rather than running `auditpol`/registry commands or scripting a rollout. That works too — the CSV and registry data in this directory is the **authoritative list of what to set**; GPMC is just an alternate **how**.

- Advanced Audit Policy subcategories (the `subcategories/*.csv` files) map to:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration`
- Administrative Templates values (`registry-settings.csv`) map to:
  `Computer Configuration -> Policies -> Administrative Templates`

Open each CSV, find the matching policy node in GPMC, and set it to the same value by hand. There is no functional difference between setting a value via GPMC and via `auditpol`/registry — GPMC ultimately writes the same underlying policy state.

## File index

| File | Contents |
|---|---|
| [`subcategories/workstation-baseline.csv`](subcategories/workstation-baseline.csv) | Baseline `auditpol` subcategory settings for domain-joined workstations. |
| [`subcategories/workstation-advanced.csv`](subcategories/workstation-advanced.csv) | Advanced (extended) `auditpol` subcategory settings for workstations. |
| [`subcategories/server-baseline.csv`](subcategories/server-baseline.csv) | Baseline `auditpol` subcategory settings for member servers. |
| [`subcategories/server-advanced.csv`](subcategories/server-advanced.csv) | Advanced `auditpol` subcategory settings for member servers. |
| [`subcategories/domain-controller-baseline.csv`](subcategories/domain-controller-baseline.csv) | Baseline `auditpol` subcategory settings for domain controllers. |
| [`subcategories/domain-controller-advanced.csv`](subcategories/domain-controller-advanced.csv) | Advanced `auditpol` subcategory settings for domain controllers. |
| [`subcategories/certificate-authority-baseline.csv`](subcategories/certificate-authority-baseline.csv) | Baseline `auditpol` subcategory settings for AD Certificate Services (CA) servers. |
| [`subcategories/certificate-authority-advanced.csv`](subcategories/certificate-authority-advanced.csv) | Advanced `auditpol` subcategory settings for AD Certificate Services (CA) servers. |
| [`registry-settings.csv`](registry-settings.csv) | Administrative Templates registry values not covered by `auditpol` (PowerShell logging, process creation command line, event log size/retention, etc.), applicable to all roles. |
