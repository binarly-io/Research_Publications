#  Data-only Attacks Against UEFI BIOS
What comes to your mind when you hear about UEFI BIOS vulnerabilities? For a long time the obvious answer was issues in SMM (System Management Mode) code, which enables one of the protection mechanisms against UEFI BIOS modifications. This was the reason of creation other platform protective technologies, but still new issues in SMM keep being discovered.

Though, supported not by each OEM/IBV, there are a number of mitigations applied for SMM code. Beyond that, a lot of firmware verification techniques were introduced recently. All measures grown by vendors aimed to protect the firmware code integrity and runtime UEFI BIOS interfaces (like SMI handlers) from software attacks and hardware tampering. However, UEFI firmware architecture still allows to develop attack vectors that has almost none countermeasures nowadays and allows to bypass all known UEFI BIOS mitigations and protection technologies.

In this talk we’ll describe current UEFI BIOS security model and talk about one if its main disadvantages, which could be exploited by recently discovered vulnerabilities.

# Breaking Firmware Trust From Pre-EFI: Exploiting Early Boot Phases
Vulnerabilities in System Management Mode (SMM) and more general UEFI applications/drivers (DXE) are receiving increased attention from security researchers. Over the last 9 months, the Binarly efiXplorer team disclosed 42 high-impact vulnerabilities related to SMM and DXE firmware components. But newer platforms have significantly increased the runtime mitigations in the UEFI firmware execution environment (including SMM). The new Intel platform firmware runtime mitigations reshaped the attack surface for SMM/DXE with new Intel Hardware Shield technologies applied below-the-OS. 

The complexity of the modern platform security features is growing every year. The general security promises of the platform consist of many different layers defining their own security boundaries. Unfortunately, in many cases, these layers may introduce inconsistencies in mitigation technologies and create room for breaking general security promises, allowing for successful attacks.

In this presentation, we will share our work exploring recent changes in the UEFI firmware security runtime using one of the most recent Intel CPUs as an example. The presentation will cover the evolution of firmware mitigations in SMM/DXE on x86-based CPUs and a discussion about the new attacks on Intel Platform Properties Assessment Module (PPAM), which are often used in tandem with Intel SMI Transfer Monitor (STM). 

These topics have never been publicly discussed from the offensive security research perspective.

## Conferences:
[H2HC 2022](https://www.h2hc.com.br/h2hc/pt/palestrantes)
