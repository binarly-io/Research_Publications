# Signed and Dangerous: BYOVD Attacks on Secure Boot

Bring Your Own Vulnerable Driver (BYOVD) is an attack technique where adversaries install legitimate but vulnerable drivers to bypass security mechanisms, execute arbitrary code, and maintain persistent control over compromised systems. 

Historically, most attention in this area has been focused on Windows drivers but can this concept be adapted to apply elsewhere? This talk explores BYOVD attacks within the UEFI ecosystem, focusing on their implications for Secure Boot. This defense represents a critical component of boot security as it is designed to maintain the Chain of Trust connecting the firmware to the operating system. Compromising Secure Boot breaks this chain, with significant consequences in terms of security.

Our talk presents the first large-scale census of signed UEFI modules drawn from public threat intel feeds and private telemetry. We classify tens of thousands of binaries, build a taxonomy of their privilege boundaries, and map out the dark corners where over-privileged, under-scrutinized code lives. In the process we uncover dozens of previously unreported Secure Boot bypasses.

We will walk the audience through three real bypass chains, demonstrate live exploitation against a fully patched machine, and show how EDR technologies can be blinded long before their kernel driver loads. 

We will outline a practical hardening roadmap for firmware vendors, OEMs, and defenders, so that the problems identified during this research can be mitigated and avoided in the future.

Finally, we will unveil the details behind CVE-2025-6198, a BMC-related security issue that allows attackers to directly “bring your own vulnerable firmware image”.

## Poc Demos
[Combining a Secure Boot Bypass with a Bootkit on Windows 11](https://www.youtube.com/watch?v=TnECRMf2CoQ)

[Supermicro BMC firmware update validation bypass (CVE-2025-7937)](https://www.youtube.com/watch?v=26kctSgJoxs)

## Conferences:
[LABScon 2025](https://www.labscon.io/)
