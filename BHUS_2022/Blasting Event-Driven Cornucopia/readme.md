# Event-Driven Cornucopia is Blasted: User-Space Attacks Blind WMI

Endpoint Detection and Response (EDR) solution architects always find new ways of monitoring OS events to mitigate security threats on endpoints. Therefore, security experts have to reuse different Windows build-in mechanisms that were not initially designed for security and can be disabled. 

Event Tracing for Windows (ETW) is one such mechanism commonly used by various security solutions. However, ETW disabling results in blinding the whole class of EDR and Anti-Virus solutions. 

Windows Management Instrumentation (WMI) is another example of Windows mechanisms that allows filtering without registering kernel callbacks or using mini-filters.  WMI is a built-in feature, designed to manage enterprise infrastructure and to provide its detailed diagnostics: hardware, software, and their configurations both locally and remotely. WMI is deeply integrated into the Windows user-mode apps and kernel drivers. WMI allows to get rich information about the computing environment and control the OS without directly calling WinAPI functions that can be tampered by malware.

WMI allows fine-grainedmonitoring by using event filters, providers, consumers, and  bindings to get notifications about various events, such as process launching, drivers loading, and files creating.

These features make WMI a cornucopia for EDR\AV, malware sandboxes, and other security sensors. The bad news for defenses is that WMI is vulnerable: malware countermeasures can disable WMI making the whole class of defense solutions totally useless. 

We will give the analysis of WMI architecture, uncover some WMI internals: reversing user-mode variable and functions from WMI DLLs to demonstrate several new user-mode attacks on WMI. These attacks blind WMI-based defense products and block effective maintenance of computer environments, which thwarts businesses from working efficiently. Binarly Sensor, a newly released tool can detect all these attacks. 

The core vulnerability of WMI is that there are DLLs loaded into the WMI core process (WinMgmt), such as wbemcore.dll, repdrvfs.dll, fastprox.dll include some “flags” involved in WMI operations. 

Attackers can block the access to the WMI by modifying these flags. As a result, WMI-based tools stop receiving new OS events, cannot install new WMI filters or get any information using WMI API. There are no built-in features to block these attacks or repair WMI.  A new protection tool, called Binarly Sensor, can reveal all these attacks by inspecting memory of WMI core service. It can disclose various attacks on the Windows OS. These attacks impact all versions of Windows from Vista to 11, which is crucial for the design of the core features of WMI.

## Conferences:

[Black Hat USA 2022]

[Black Hat USA 2022]: <https://www.blackhat.com/us-22/briefings/schedule/#blasting-event-driven-cornucopia-wmi-based-user-space-attacks-blind-siems-and-edrs-27211>