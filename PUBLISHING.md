# Kali submission notes

Package: `scopewatch`
Version: `0.1.0`
License: MIT
Homepage: `https://github.com/zipperswag111/scopewatch`
Maintainer: `scopewatch contributors <maintainers@scopewatch.invalid>`

## Description

scopewatch is an authorized external asset-drift auditor. It normalizes evidence from certificate transparency, optional licensed passive-DNS providers, user-supplied historic FDNS data, and optional wordlist candidates. It makes provenance visible and prevents wordlist candidates from being represented as observed assets. Optional verification performs DNS resolution only.

## Similar tools

Amass and subfinder provide broad subdomain enumeration; httpx and naabu provide subsequent probing. scopewatchâs narrower focus is evidence status, provenance, and historic drift in an explicit authorization workflow.

## Dependencies

- Python 3.10+
- No third-party runtime Python dependencies
- Optional: SecLists, user API keys for SecurityTrails / WhoisXML, a user-downloaded Rapid7 FDNS file

## Activity

Initial release: 2026. Continued development should be tracked through GitHub issues and releases.
