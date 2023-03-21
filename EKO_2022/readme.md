# Breaking Firmware Trust From Pre-EFI: Exploiting Early Boot Phases
Vulnerabilities in System Management Mode (SMM) and more general UEFI applications/drivers (DXE) are receiving increased attention from security researchers. Over the last 9 months, the Binarly efiXplorer team disclosed 42 high-impact vulnerabilities related to SMM and DXE firmware components. But newer platforms have significantly increased the runtime mitigations in the UEFI firmware execution environment (including SMM). The new Intel platform firmware runtime mitigations reshaped the attack surface for SMM/DXE with new Intel Hardware Shield technologies applied below-the-OS.

The complexity of the modern platform security features is growing every year. The general security promises of the platform consist of many different layers defining their own security boundaries. Unfortunately, in many cases, these layers may introduce inconsistencies in mitigation technologies and create room for breaking general security promises, allowing for successful attacks.

In this presentation, we will share our work exploring recent changes in the UEFI firmware security runtime using one of the most recent Intel CPUs as an example. The presentation will cover the evolution of firmware mitigations in SMM/DXE on x86-based CPUs and a discussion about the new attacks on Intel Platform Properties Assessment Module (PPAM), which are often used in tandem with Intel SMI Transfer Monitor (STM).

These topics have never been publicly discussed from the offensive security research perspective.

## Conferences:
**Ekoparty 2022** [video](https://www.youtube.com/watch?v=G8fjXBCddMw)

