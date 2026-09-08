# Security Policy

`crypto-toolkit` is a cryptography library; vulnerabilities in it directly affect
every downstream user. Please report issues responsibly.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of:

- **GitHub Private Vulnerability Reporting**: use the "Report a vulnerability"
  button on the repository's Security tab
  (<https://github.com/parthivrawat/crypto-toolkit/security/advisories/new>)
- **Email**: parthiv05022000@gmail.com — include "crypto-toolkit security" in
  the subject line

Please include:

- Which language package(s) and version(s) are affected
- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept, if possible

You can expect an acknowledgement within 72 hours. We will coordinate a fix and
a disclosure timeline with you, and credit you in the release notes unless you
prefer to remain anonymous.

## Supported Versions

Only the latest minor release of each language package receives security fixes.

| Package | Supported versions |
|---|---|
| `crypto-toolkit` (Go) | 1.x (latest) |
| `crypto-toolkit-py` (Python) | 1.x (latest) |
| `modern-crypto-toolkit` (Rust) | 1.x (latest) |
| `crypto-toolkit-ts` (TypeScript) | 1.x (latest) |

## Scope

In scope:

- Cryptographic weaknesses in the implementations (nonce reuse, insecure
  defaults, missing authentication, weak algorithm acceptance)
- Constant-time / timing issues in verification paths
- Memory handling issues that expose key material
- Serialization/parsing bugs that bypass verification

Out of scope:

- Attacks requiring physical access or a compromised host
- Side-channel attacks beyond reasonable constant-time practice
  (e.g., EM/Acoustic analysis)
- Issues in third-party dependencies — report those upstream; we track them via
  `govulncheck`, `pip-audit`, `cargo audit`, and `npm audit` in CI

## Disclosure Policy

- Fixes are developed privately and released in a coordinated patch across all
  affected language packages.
- A GitHub Security Advisory (GHSA) is published at release time with CVE
  assignment when warranted.
- Reporters are asked to allow 90 days for remediation before public disclosure.
