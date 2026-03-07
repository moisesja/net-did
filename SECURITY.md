# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in NetDid, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email the maintainer directly with a description of the vulnerability
2. Include steps to reproduce, if possible
3. Allow reasonable time for a fix before public disclosure

### What to Expect

- Acknowledgment within 48 hours
- A plan for remediation within 7 days
- Credit in the security advisory (unless you prefer to remain anonymous)

## Scope

Security issues in the following areas are in scope:

- **Cryptographic operations**: Incorrect key generation, signing, verification, or key agreement
- **Key material handling**: Private key exposure, insufficient entropy, improper cleanup
- **Serialization/parsing**: Injection attacks via DID Documents, malformed input handling
- **DID resolution**: Resolution result spoofing, cache poisoning

## Out of Scope

- Vulnerabilities in upstream dependencies (report these to the respective project)
- Denial of service through resource exhaustion (unless trivially exploitable)
- Issues requiring physical access to the host machine

## Best Practices for Users

- Never log or serialize private key material
- Use `IKeyStore` implementations backed by HSM or secure enclaves in production
- The included `InMemoryKeyStore` is for development and testing only
- Validate DID Documents from untrusted sources before trusting verification methods
