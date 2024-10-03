# PKFAIL: Supply-Chain Failures in Secure Boot Key Management

Modern computing heavily relies on establishing and maintaining trust, which begins with trusted foundations and extends through operating systems and applications in a chain-like manner. This ensures that end users can confidently rely on the integrity of the underlying hardware, firmware, and software. One of the most prevalent mechanisms for enforcing trust in the UEFI firmware ecosystem is Secure Boot. Secure Boot ensures that only digitally signed and verified software is executed during the system boot process, safeguarding against attacks on “external” firmware components and boot loaders. A key component of Secure Boot is the Platform Key (PK), the root-of-trust key used for managing the cryptographic material that validates external components and bootloaders before execution. Given its critical role, one would expect all best practices for cryptographic key management to be meticulously followed… right?

In this talk we will unveil PKFAIL, a firmware supply-chain security issue affecting major device vendors and hundreds of device models. PKFAIL is the result of shipping default test keys included by IBVs in their reference implementation—a problem that is already known since 2016 but was clearly forgotten by the firmware industry. Given these test keys leaked during the various data breaches of the past few years, an attacker can leverage PKFAIL to completely bypass Secure Boot on affected devices. As we will demonstrate during our presentation, PKFAIL makes it extremely straightforward to bootkit affected devices and to launch advanced firmware-level threats, such as BlackLotus.

In our presentation, we will also offer a retrospective industry-wise analysis on PKFAIL, based on our extensive dataset of UEFI firmware images, spanning hundreds of product lines marketed over the past decade.

## Poc Demos
[Proof of Concept for PKfail](https://www.youtube.com/watch?v=SPl7zfC-CmQ)

[Proof of Concept for PKfail (Linux version)](https://www.youtube.com/watch?v=CveWt3gFQTE)

## Conferences:
[LABScon 2024](https://www.labscon.io/)
