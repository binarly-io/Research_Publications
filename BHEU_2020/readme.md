# efiXplorer: Hunting for UEFI Firmware Vulnerabilities at Scale with Automated Static Analysis

Existing UEFI analysis instruments lack systemic approach to firmware vulnerability research focused on specifics of x86-based systems. No publicly known tools available for UEFI firmware vulnerabilities research focused on static analysis. Most of the common reversing tools focused on simplifying some reconstruction routines but not rebuilding the full picture based on firmware image. Previously, researchers have presented some work on statically analyzing UEFI firmware images at scale but more focused on misconfiguration issues (like Secure Boot not enabled or firmware update is not authenticated).

In our talk, we will introduce a vulnerability research approach with unique static analysis sauce aimed to find vulnerable code patterns. efiXplorer plugin REconstructs key elements and data types (like EFI protocols) with cross-references (by analyzing the full firmware image) valuable for UEFI reverse engineering. Without reconstruction cross-references, it's hard to find classes of issues such as SMM (Intel System Management Mode) callout (where a pointer is referencing a not validated buffer in untrusted memory (NVRAM, ACPI ...) controlled by the attacker) and others.

efiXplorer IDA plugin - Most comprehensive open-source IDA plugin for UEFI reverse engineering. Authors open-sourced this plugin recently and continue to work on it focusing more on vulnerability research.

The presented IDA plugin discovered multiple previously unreported vulnerabilities in recent widespread hardware platforms from common vendors (like ASUS, ASRock, MSI, Gigabyte, Lenovo, and some others). In this Briefing, we will push a new version of the plugin with functionality to trigger all presented classes of the issues during the talk.

## Conferences:
Black Hat Europe 2020 [video](https://www.youtube.com/watch?v=Sa779TGX3wY)
