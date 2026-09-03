# Containers Don't Keep Secrets: Scanning Docker Hub for Leaked Credentials and Private Keys

Containers promise isolation, but secrets leak through every layer: from hardcoded API keys to embedded .env files, developers often ship credentials into public images without realizing it.

This talk presents results from scanning 200 TB of Docker Hub layers. We'll cover the scanning pipeline, tooling built to process hundreds of terabytes at scale, and patterns behind how secrets reach production images. Among our findings, we discovered valid GitHub tokens from a large enterprise with privileges to clone, modify, or delete repositories, tamper with CI/CD pipelines, and access sensitive organization data. Beyond API secrets, we'll show that cryptographic private keys are also commonly embedded in containers and how this impacts SSH servers and HTTPS certificates.

Finally, we will also share the trade-offs and lessons learned from a new technique: using LLMs to validate and triage detected secrets at scale.

## Resources
[Research Blog](https://www.binarly.io/blog/docker-hub-secrets)


## Conferences:
[ContainerDays 2026](https://www.containerdays.io/)

