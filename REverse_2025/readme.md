# Near-Native Rehosting for Embedded ARM Firmware
Rehosting, the art of running the firmware in a virtualized environment, rather than on the original hardware platform, is the de-facto standard for fuzzing embedded firmware. Off-the-shelf solutions for emulation such as QEMU were not designed with fuzzing in mind, where we want to optimize for as many executions per second as feasible.

We showcase near-native rehosting: running embedded firmware as a Linux userspace process on a high-performance system that shares the instruction set family with the targeted device. After discussing the intricacies of lifting and rewriting ARM instructions, we fuzz ARM Cortex-M firmware and show that our framework, SAFIREFUZZ, can provide a 690x throughput increase on average during 24-hour fuzzing campaigns while covering up to 30% more basic blocks.

## Resources
Github: https://github.com/pr0me/SAFIREFUZZ  
Paper: https://download.vusec.net/papers/safirefuzz_sec23.pdf

#  UEFI Bootkit Hunting: In-Depth Search for Unique Code Behavior
Firmware threats such as bootkits and implants have become increasingly prevalent due to their persistence and ability to evade detection compared to traditional OS-level malware. Attackers favor these threats because they can remain undetected even when conventional security measures are in place, especially if UEFI Secure Boot is disabled through physical access or UEFI exploits. Detecting unknown bootkits under these circumstances is a critical challenge in cybersecurity. Mostly, all the publicly known UEFI implants and bootkits have been detected after successful deployment, which points to the limitations of the existing security solutions.

This presentation introduces a novel methodology for detecting UEFI bootkits by analyzing their unique code behaviors. We conducted an in-depth study of existing bootkits—including Lojax, MosaicRegressor, MoonBounce, CosmicStrand, ESPecter, and BlackLotus. During our REsearch we identified common code characteristics such as hook chains, persistence mechanisms, and other distinctive features. Leveraging these insights, we developed the methodology for generic detection techniques based on code similarity. 

In addition, we crafted Yara and FwHunt rules focusing on the OS kernel and driver hooks implemented by bootkits. Applying our approach through VirusTotal retrohunts and Binarly Risk Hunt telemetry data led to the discovery of six previously unidentified bootkit samples. Notably, three of these samples were entirely undetected by existing security tools, while the others had minimal detections but were not recognized as bootkits. These findings not only validate the effectiveness of our detection strategy but also highlight the ongoing challenges in bootkit detection within threat intelligence. By shedding light on these elusive threats, our research advances firmware security and underscores the necessity for continued efforts to enhance detection capabilities against sophisticated bootkits.

## Conferences:
[RE//verse 2025](https://re-verse.io/)
