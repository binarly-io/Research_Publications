# Signed and Dangerous: BYOVD Attacks on Secure Boot

Bring Your Own Vulnerable Driver (BYOVD) is an attack technique where adversaries install legitimate but vulnerable drivers to bypass security mechanisms, execute arbitrary code, and maintain persistent control over compromised systems. 

Historically, most attention in this area has been focused on Windows drivers but can this concept be adapted to apply elsewhere? This talk explores BYOVD attacks within the UEFI ecosystem, focusing on their implications for Secure Boot. This defense represents a critical component of boot security as it is designed to maintain the Chain of Trust connecting the firmware to the operating system. Compromising Secure Boot breaks this chain, with significant consequences in terms of security.

Our talk presents the first large-scale census of signed UEFI modules drawn from public threat intel feeds and private telemetry. We classify tens of thousands of binaries, build a taxonomy of their privilege boundaries, and map out the dark corners where over-privileged, under-scrutinized code lives. In the process we uncover dozens of previously unreported Secure Boot bypasses.

We will walk the audience through a real bypass chain, demonstrate live exploitation against a fully patched machine, and show how EDR technologies can be blinded long before their kernel driver loads. 

We will outline a practical hardening roadmap for firmware vendors, OEMs, and defenders, so that the problems identified during this research can be mitigated and avoided in the future.

Finally, we will present insights from recent research on mitigations in UEFI. This research underscores both achievements and challenges, emphasizing the need for wider adoption of mitigations in the UEFI ecosystem.

# Repeatable Supply Chain Security Failures in Firmware Key Management

Several key management failures have impacted UEFI vendors in recent years. During this talk, we'll discuss data breaches that exposed private keys — including Boot Guard keys — and explore both the immediate and ongoing consequences these incidents have had on the ecosystem. Additionally, we'll discuss how products were shipped with expired, debug, or non-production certificates, which have further increased security risks. Using the latest data from the UEFI ecosystem, we'll provide fresh insights into these persistent, long-standing issues and their current impact.

## Conferences:
[UEFI 2025 Developers Conference](https://uefi.org/events/uefi-2025-developers-conference-and-plugfest)
