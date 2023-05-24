# A Dark Side of UEFI: Cross-Silicon Exploitation

In January 2023 we disclosed multiple vulnerabilities affecting Qualcomm reference code and impacting different device vendors and IBVs (https://binarly.io/posts/Multiple_Vulnerabilities_in_Qualcomm_and_Lenovo_ARM_based_Devices). Usually, UEFI firmware related vulnerabilities are disclosed from the perspective of the x86 ecosystem on Intel or AMD based devices. This is the first public disclosure in history of UEFI specification related to the ARM device ecosystem. It shows some of the attacks and classes of bugs can be the same on both ARM and x86 devices, but exploitation specifics will be different. These vulnerabilities are confirmed on Lenovo’s Thinkpad and Microsoft’s Surface devices during our research. Even the recently released development device Microsoft Windows Dev Kit 2023 (code name “Project Volterra”) is impacted.

These three vulnerabilities BRLY-2022-029, BRLY-2022-030, BRLY-2022-033 have a high-impact CVSS score since they can lead to a secure boot bypass, and enable an attacker to gain persistence on a device by gaining sufficient privileges to write to the file system, thus allowing an attacker to cross an extra security boundary to simplify attacks on TrustZone. All three are impacting Qualcomm’s reference code and affect the entire ecosystem.

The goal of the presentation is to discuss the different aspects of unification of firmware development with frameworks like UEFI and what kind of security implications it can have from the attacker and defender perspectives.

## Conferences:
[OffensiveCon 2023](https://www.offensivecon.org/speakers/2023/alex-matrosov-and-alex-ermolov.html)