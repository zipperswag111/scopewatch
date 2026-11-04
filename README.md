# scopewatch

`scopewatch` is an evidence-first, authorized external asset-drift auditor. It brings passive evidence, user-licensed provider APIs, optional local Rapid7 Sonar FDNS baselines, and optional wordlist candidates into one small, reviewable report.

It is deliberately **not** a mass scanner, exploit tool, login tester, credential tool, or brute-force engine. By default it makes only passive-source requests. DNS resolution is opt-in.

## Why it exists

Kali already ships excellent discovery tools. `scopewatch` is meant to answer the later operational question: *which assets are new, historic, still verified, or merely candidates â and what evidence supports that label?*

Every record has one status:

| Status | Meaning |
| --- | --- |
| `observed` | Passive source or licensed provider reported it. |
| `historic` | Present in a user-supplied historic FDNS baseline. |
| `candidate` | Generated from a wordlist; not treated as a discovered asset. |
| `verified` | DNS resolution succeeded after explicit `--verify-dns`. |
| `source-error` | A source could not be reached; not an asset result. |

## Safety and authorization

Create a scope file before use. The explicit acknowledgement is required:

```json
{
  "authorization": "I_AM_AUTHORIZED_TO_TEST_THESE_ASSETS",
  "domains": ["example.com"],
  "owner": "Engagement reference"
}
```

Only list assets you own or are explicitly authorized to assess. API keys are read only from your local environment; they are never stored in reports.

## Install

```bash
python3 -m pip install .
scopewatch --version
```

For a local Debian package:

```bash
dpkg-buildpackage -us -uc -b
sudo apt install ../scopewatch_0.1.0-1_all.deb
```

## Examples

Passive Certificate Transparency only:

```bash
scopewatch discover --scope example-scope.json --source crt --output findings.json
```

Use optional licensed APIs and explicitly opt into DNS resolution:

```bash
export SCOPEWATCH_SECURITYTRAILS_API_KEY='your-key'
export SCOPEWATCH_WHOISXML_API_KEY='your-key'
scopewatch discover --scope example-scope.json \
  --source crt --source securitytrails --source whoisxml --verify-dns \
  --output findings.json
```

Add an open wordlist only as **candidates** and a locally downloaded Rapid7 FDNS baseline only as **historic** evidence:

```bash
scopewatch discover --scope example-scope.json \
  --wordlist /usr/share/seclists/Discovery/DNS/combined_subdomains.txt \
  --fdns-file /data/sonar.fdns_v2.json.gz --verify-dns
```

## Data-source policy

- **Certificate Transparency:** retrieved from `crt.sh` at runtime.
- **SecurityTrails / WhoisXML:** optional account-backed APIs. You must have your own key and comply with each providerâs terms; scopewatch does not bundle, mirror, or redistribute their data.
- **Rapid7 Sonar FDNS:** optional user-supplied local baseline. Download and licensing are the userâs responsibility.
- **Assetnote / SecLists / Trickest wordlists:** optional input only. They produce `candidate` labels, never passive evidence.

## Debian packaging

The repository includes `debian/` metadata for a source package. The intended package name and command are both `scopewatch`. Before an official Kali submission, maintainers should review Debian policy, copyright/provenance for any added data, and overlap with existing Kali tooling.

## License

MIT. See [LICENSE](LICENSE).
