# VulHunt: A Framework for Hunting Vulnerabilities in Binaries

With the increasing complexity of software and the growing number of dependencies, the number of reported vulnerabilities continues to rise each year. Traditional methods for identifying these vulnerabilities--primarily based on library version detection or signature matching--often fail to account for applied patches, leading to inaccurate results, false positives and alert fatigue.  

To tackle this industry-wide challenge, we present VulHunt, a framework designed to be used both by LLMs and domain experts. It enables the creation of rule-based analyses to detect vulnerabilities in binaries by examining intrinsic program characteristics through structural, semantic, and syntactic patterns. VulHunt’s engine capabilities can be leveraged by LLM-based tooling to assist in triaging and actively hunting vulnerabilities, while its rule engine can be leveraged for variant hunting and patch validation. This approach allows VulHunt to identify vulnerabilities independently of binary versions and architectures, minimizing false positives while supporting sufficiently general rules to detect previously unknown flaws.

In this talk, we will walk through VulHunt’s capabilities, showing how its components are leveraged for effective vulnerability detection. We will highlight key features such as its dataflow engine, intermediate representation matching, pattern matching over decompiled code and raw bytes, the integration of signatures to enhance coverage, and support for type libraries to improve explainability. Finally, we will demonstrate how VulHunt applies across common vulnerability use cases and conclude with the identification of a real-world vulnerability.

## Demos
[VulHunt at Scale](https://youtu.be/eT68BMqL5DY)

[VulHunt Capabilities](https://youtu.be/1-L0FnXC9eQ)

[VulHunt Rules: Detecting Real-World Vulnerabilities](https://youtu.be/jwTxdovsJUs)

[VulHunt's LLM Integration: Vulnerability Triaging](https://youtu.be/ycXcRGgriE0)

[VulHunt's LLM Integration: Vulnerability Hunting](https://youtu.be/S9x8m-TxP20)

## Resources
[GitHub](https://github.com/vulhunt-re/vulhunt)

[Documentation](https://vulhunt.re/docs/)

## Conferences:
[RE//verse 2026](https://re-verse.io/)

