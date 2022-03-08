# UEFI Firmware Vulnerabilities: Past, Present and Future

For any device, the supply chain is extremely complex and it plays a significant role in the platform security. The UEFI System Firmware relies heavily on its supply chain with many parties involved, including OBV, IBV, OEM etc. each following their own development lifecycle, mitigations policy and impacting different security models and update delivery timeline for endpoint devices. 

This obviously creates some space for building and supporting exploit chains for compromising firmware: a single vulnerability can be replaced by another one of the same class and live long enough until it will be patched by the vendor...guess how long will it take? Six months, a year or maybe two? Quite a while to deliver security, right? But how about 6 years? We're going to talk about a very interesting case: a security issue (one bug in the same EFI module), which survived across time, mitigations, multiple attempts to fix it, platform changes, pandemic, rain and thunder. This research covers architectural problems - an actual root-cause not only for this issue but other UEFI firmware vulnerabilities now and then.

## Conferences:
[OffensiveCon 2022](https://www.offensivecon.org/speakers/2022/alex-ermolov,-alex-matrosov-and-yegor-vasilenko.html)
