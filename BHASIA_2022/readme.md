# The Firmware Supply-Chain Security Is Broken: Can We Fix It?
Nowadays, it's difficult to find any hardware vendor who develops all the components present in its products. Many of these components, including firmware, are outsourced to ODMs. As a result, this limits the ability of hardware vendors to have complete control over their hardware products. In addition to creating extra supply chain security risks, this also produces security gaps in the threat modeling process. Through this research, ​we wanted to raise awareness about the risks in the firmware supply chain and the complexity of fixing known vulnerabilities.

The firmware patch cycles last typically around 6-9 months (sometimes even longer) due to the complexity of the firmware supply chain and the lack of a uniform patching process. The 1-day and n-day vulnerabilities in many cases have a large impact on enterprises since the latest firmware update wasn't installed or the device vendor had not released a patch yet. Each vendor follows their own patch cycle. Even known issues may not be patched until the next firmware update is available.

We decided to build an open-source framework to identify known vulnerabilities in the context of UEFI specifics, classify them based on their impact and detect across the firmware ecosystem with the help of the LVFS project. We will be sharing our approach as well as the tooling we have created to help the industry identify the problems and get patched.

## Conferences:
[Black Hat Asia 2022](https://www.blackhat.com/asia-22/briefings/schedule/index.html#the-firmware-supply-chain-security-is-broken-can-we-fix-it-26175)
