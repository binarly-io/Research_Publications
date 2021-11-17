# Veni, No Vidi, No Vici: Attacks on ETW Blind EDR Sensors

Event Tracing for Windows (ETW) is a built-in feature, originally designed to perform software diagnostics, and nowadays ETW is essential for Endpoint Detection & Response (EDR) solutions. ETW is deeply integrated into the Windows kernel and involved in many API calls to trace OS events. ETW functions are used by numerous EDRs, business and academic projects to respond to security threats.

The bad news for defenses is that ETW is vulnerable: malware countermeasures can disable ETW making the whole class of EDRs totally useless.

We will give an analysis of the existing attacks on ETW, uncover some ETW internals: data structures and reversing kernel API routines to demonstrate two new attacks on ETW. These attacks blind ETW-based EDRs, without triggering any OS security features, such as KPP. A newly released tool Binarly Sensor can detect both attacks, while an updated MemoryRanger can prevent only the second one.

The first attack is focused on NT Kernel Logger Session. Process Monitor collects network events by using this logger. To blind Process Monitor, we will use an app to illegally stop a running NT Kernel Logger Session. Circular Kernel Context Logger and other logger sessions can be attacked similarly.
The second attack is focused on ETW Logger sessions used by Windows Defender. The attack is based on patching ETW data structures. We will demonstrate a kernel driver to query information and stop ETW Logger sessions, which results in disabling defense mechanisms.

A new protection tool, called Binarly Sensor, can reveal both attacks. It uses a kernel driver to extract information about critical OS data and code. It can disclose various attacks on the Windows kernel.

These attacks impact all versions of Windows from Vista to 11, which is crucial for the design of the core features of ETW.

## PoC Demos
[Hijacking ETW sessions for Process Monitor](https://www.youtube.com/watch?v=7jmjqnrwX2M)

[Attack on Windows Defender ETW sessions](https://www.youtube.com/watch?v=SxrqaIlY488)

[Preventing the Attack on Windows Defender ETW sessions](https://www.youtube.com/watch?v=62CmVadzZPQ)

## Conferences:
[Black Hat Europe 2021](https://www.blackhat.com/eu-21/briefings/schedule/index.html#veni-no-vidi-no-vici-attacks-on-etw-blind-edr-sensors-24842)
