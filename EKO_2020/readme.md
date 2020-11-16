# Static analysis-based recovery of service function calls and type information in UEFI firmware
Reversing UEFI firmware requires a lot of background and knowledge about firmware and understanding of hardware before you can start hunting for vulnerabilities. Existing UEFI analysis instruments lack a systemic approach to firmware vulnerability research focused on specifics of x86-based systems. No publicly known tools available for UEFI firmware vulnerabilities research focused on static analysis. Most of the common reversing tools focused on simplifying some reconstruction routines but not rebuilding the full picture based on the firmware image.

This talk will focus on the discussion around existing UEFI RE plugins for Ghidra and IDA with an explanation of why we decide to start the work on a new tool [efiXplorer](https://github.com/binarly-io/efiXplorer). With our new tool, we automatically recover services calls and EFI type info, so that a firmware code looks like original source.

## Conferences:
**Ekoparty 2020 ** [video](https://www.youtube.com/watch?v=rK0tmVa19ME)

