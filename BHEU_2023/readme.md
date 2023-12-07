# LogoFAIL: Security Implications of Image Parsing During System Boot

Everyone loves to customize and personalize their own devices: from text editors to background pictures, from operating systems to keyboard shortcuts, each device is almost unique. One of the most exotic customizations, done either for personal tastes or for company branding, is personalizing the logo displayed by the BIOS during boot. But what are the security implications of parsing user-supplied (a.k.a. "attacker-controlled") logo images during boot? Aren't we jumping back straight to 2009, when Rafal Wojtczuk and Alexander Tereshkin exploited a BMP parser bug in UEFI reference code… right?!

Enter LogoFAIL, our latest research revealing significant security vulnerabilities in the image parsing libraries used by nearly all BIOS vendors to display logo images during boot. Our research highlights the risks associated with parsing complex file formats at such a delicate stage of the platform startup. During this talk, we will show how some UEFI BIOSes allow attackers to store custom logo images, which are parsed during boot, on the EFI system partition (ESP) or inside unsigned sections of a firmware update. We also shed light on the implications of these vulnerabilities, which extend beyond mere graphical rendering. In fact, successful exploitation of these vulnerabilities allows attackers to hijack the execution flow and achieve arbitrary code execution. LogoFAIL vulnerabilities can compromise the security of the entire system rendering "below-the-OS" security measures completely ineffective (e.g., Secure Boot). Finally, our talk will include a detailed explanation of how we successfully escalate privileges from OS to firmware level by exploiting a real device vulnerable to LogoFAIL.

We disclosed our findings to different device vendors (Intel, Acer, Lenovo) and to the major UEFI IBVs (AMI, Insyde, Phoenix). While we are still in the process of understanding the actual extent of LogoFAIL, we already found that hundreds of consumer- and enterprise-grade devices are possibly vulnerable to this novel attack.

## Poc Demos
[Finding LogoFAIL: The Dangers of Image Parsing During System Boot](https://www.youtube.com/watch?v=EufeOPe6eqk)

## Conferences:
[Black Hat Europe 2023](https://www.blackhat.com/eu-23/briefings/schedule/index.html#logofail-security-implications-of-image-parsing-during-system-boot-35042)
