# Sysmon

Applies to Windows Server 2016+ and Windows 10/11. This is a short bridge document, not a Sysmon guide — it explains why Sysmon belongs alongside native Windows Security auditing in this repo's pipeline and where its events land, then points elsewhere for everything else.

## Why Sysmon complements native auditing

Native Windows Security auditing, however thoroughly tuned with `auditpol`, has hard ceilings: it cannot tell you which remote address and port a process connected to, which images and DLLs a process loaded and whether they were signed, when a process opens a handle to another process's memory with a specific access mask, raw disk or volume reads that bypass the filesystem, DNS queries a process issued, or named pipe creation and connection. These are exactly the gaps Sysmon fills — it's a kernel-level monitor purpose-built to capture that class of activity, so pairing it with the Security log gives you both sides: what native auditing already covers well (logons, object access, privilege use, account management) and the process- and network-level detail that no amount of `auditpol` configuration will ever expose.

## How it fits into this repo's collection pipeline

Once installed, Sysmon writes its events to the `Microsoft-Windows-Sysmon/Operational` log — a standard Windows Event Log channel like any other, which means it needs no separate collection mechanism. It's forwarded and collected the same way as everything else covered in this guide: via Windows Event Forwarding (see [`collection/windows-event-forwarding.md`](windows-event-forwarding.md)) or via a SIEM agent (see [`collection/siem-forwarders.md`](siem-forwarders.md)). Just add the `Microsoft-Windows-Sysmon/Operational` channel to your subscription or agent configuration alongside the Security log.

For installation, configuration, and event-by-event reference, see the [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) — this repo doesn't duplicate that content.
