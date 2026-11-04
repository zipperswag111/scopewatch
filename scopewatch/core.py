"""Core scope checks, passive collection and evidence normalization."""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


USER_AGENT = "scopewatch/0.1 (+https://github.com/zipperswag111/scopewatch)"


@dataclass(frozen=True)
class Finding:
    hostname: str
    status: str
    source: str
    evidence: str
    observed_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def in_scope(hostname: str, root_domain: str) -> bool:
    host, root = normalize_host(hostname), normalize_host(root_domain)
    return host == root or host.endswith("." + root)


def read_scope(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("authorization") != "I_AM_AUTHORIZED_TO_TEST_THESE_ASSETS":
        raise ValueError("scope file must contain the required authorization acknowledgement")
    domains = data.get("domains")
    if not isinstance(domains, list) or not all(isinstance(x, str) and x for x in domains):
        raise ValueError("scope file must contain a non-empty domains list")
    return data


def fetch_json(url: str, headers: dict[str, str] | None = None) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def crtsh(domain: str) -> list[Finding]:
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%25." + domain, "output": "json"})
    try:
        rows = fetch_json(url)
    except Exception as exc:  # network availability is not a finding
        return [Finding(domain, "source-error", "crt.sh", type(exc).__name__, now())]
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = normalize_host(name.lstrip("*."))
            if in_scope(name, domain):
                names.add(name)
    return [Finding(name, "observed", "crt.sh", "certificate-transparency", now()) for name in sorted(names)]


def provider_subdomains(domain: str, provider: str, api_key: str) -> list[Finding]:
    if provider == "securitytrails":
        url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain)}/subdomains"
        headers = {"APIKEY": api_key}
        payload = fetch_json(url, headers)
        names = [f"{label}.{domain}" for label in payload.get("subdomains", [])]
    elif provider == "whoisxml":
        url = "https://subdomains.whoisxmlapi.com/api/v1?" + urllib.parse.urlencode({"apiKey": api_key, "domainName": domain})
        payload = fetch_json(url)
        names = payload.get("result", {}).get("records", [])
    else:
        raise ValueError(f"unsupported provider: {provider}")
    return [Finding(normalize_host(name), "observed", provider, "provider-api", now()) for name in names if in_scope(str(name), domain)]


def candidates(domain: str, wordlist: str | Path, limit: int = 5000) -> list[Finding]:
    labels = Path(wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()[:limit]
    result = []
    for label in labels:
        label = label.strip().lower().strip(".")
        if label and all(ch.isalnum() or ch == "-" or ch == "." for ch in label):
            result.append(Finding(f"{label}.{domain}", "candidate", "wordlist", str(wordlist), now()))
    return result


def fdns_baseline(domain: str, filename: str | Path, limit: int = 500000) -> list[Finding]:
    path = Path(filename)
    opener = gzip.open if path.suffix == ".gz" else open
    hits: set[str] = set()
    with opener(path, "rt", encoding="utf-8", errors="ignore") as handle:
        for index, line in enumerate(handle):
            if index >= limit:
                break
            # Sonar FDNS archives are CSV. Search only hostname-bearing cells.
            for cell in next(csv.reader([line]), []):
                host = normalize_host(cell)
                if in_scope(host, domain):
                    hits.add(host)
    return [Finding(host, "historic", "rapid7-fdns", str(path), now()) for host in sorted(hits)]


def verify_dns(findings: list[Finding]) -> list[Finding]:
    verified = []
    for finding in findings:
        if finding.status == "source-error":
            verified.append(finding)
            continue
        try:
            infos = socket.getaddrinfo(finding.hostname, None, type=socket.SOCK_STREAM)
            addresses = sorted({item[4][0] for item in infos})
            verified.append(Finding(finding.hostname, "verified", finding.source, "dns:" + ",".join(addresses), finding.observed_at))
        except socket.gaierror:
            verified.append(finding)
    return verified


def dedupe(findings: list[Finding]) -> list[Finding]:
    priority = {"verified": 4, "observed": 3, "historic": 2, "candidate": 1, "source-error": 0}
    chosen: dict[str, Finding] = {}
    for finding in findings:
        previous = chosen.get(finding.hostname)
        if previous is None or priority[finding.status] > priority[previous.status]:
            chosen[finding.hostname] = finding
    return sorted(chosen.values(), key=lambda item: (item.status, item.hostname))


def write_json(findings: list[Finding], destination: str | Path) -> None:
    Path(destination).write_text(json.dumps([item.to_dict() for item in findings], indent=2) + "\n", encoding="utf-8")
