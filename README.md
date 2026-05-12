# webrecon

Automated reconnaissance pipeline with:

- subdomain discovery (`subfinder`)
- live host probing (`httpx`)
- crawling (`katana`)
- content/path discovery (`dirsearch`)
- vulnerability scanning (`nuclei`)
- differential change tracking (`diff mode`)
- webhook alerts for high-signal new findings
- HTML and master text reporting
- optional built-in web UI

## 1. Requirements

Install these tools and make sure they are in `PATH`:

- `subfinder`
- `httpx` (ProjectDiscovery version)
- `katana`
- `dirsearch`
- `nuclei`
- `go` (required when using `webrecon.sh` wrapper)

Example installs (Go-based tools):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

For `dirsearch`, use your distro package manager or clone from the official repo.

## 2. Build and run

### Option A: use the shell wrapper

```bash
chmod +x webrecon.sh
./webrecon.sh -d example.com
```

### Option B: build binary directly

```bash
go build -o webrecon webrecon.go
./webrecon -d example.com
```

## 3. CLI usage

```text
Usage: webrecon [OPTIONS]

Options:
    -d, --domain DOMAIN         Single domain to scan
    -l, --list FILE             File containing list of domains
    -o, --output DIR            Output directory (default: recon_results)
    -p, --profile PROFILE       Scan profile: quick|standard|deep (default: standard)
    -ns, --nuclei-severity S    Nuclei severities (comma-separated)
    --diff                      Compare current run with previous run
    --diff-base TS              Use specific baseline timestamp (YYYYMMDD_HHMMSS)
    --webhook-url URL           Send diff alerts to webhook URL
    --web                       Start web interface mode
    --web-addr ADDR             Web bind address (default: 127.0.0.1:8080)
    -t, --threads NUM           Threads for httpx (default: 50)
    -rl, --rate-limit NUM       Rate limit for httpx (default: 150)
    -kd, --katana-depth NUM     Crawl depth for katana (default: 3)
    -kw, --katana-workers NUM   Parallel katana workers (default: CPU count)
    -dt, --dirsearch-threads N  Dirsearch threads per host (default: 30)
    -dr, --dirsearch-recursive  Enable recursive dirsearch
    -h, --help                  Show this help message
```

## 4. Profiles

`--profile` auto-tunes scan intensity.

| Profile | Behavior |
|---|---|
| `quick` | Lower threads/rate/depth, faster pass, defaults nuclei to `high,critical` |
| `standard` | Balanced defaults |
| `deep` | Higher threads/rate/depth, recursive dirsearch enabled, wider nuclei severities (`low,medium,high,critical`) |

You can still override any value with flags (`-t`, `-rl`, `-kd`, `-kw`, `-dt`, `-dr`, `-ns`).

## 5. Diff mode and alerts

Diff mode compares your current run against a previous baseline and generates:

- added/removed subdomains
- added/removed live hosts
- added/removed URLs
- added/removed dirsearch paths
- new/resolved nuclei findings

Usage:

```bash
# compare with latest previous run
./webrecon -d example.com --diff

# compare with specific baseline timestamp
./webrecon -d example.com --diff --diff-base 20260513_010203
```

Webhook alerts:

```bash
./webrecon -d example.com --diff --webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ
```

Alert is sent when diff mode finds:

- new high/critical nuclei findings
- new high-risk discovered paths

## 6. Web UI mode

Start server:

```bash
./webrecon --web --web-addr 127.0.0.1:8080
```

Open in browser:

```text
http://127.0.0.1:8080
```

Web UI includes:

- scan form (domain/domain list, output dir, profile, nuclei severity, diff settings, webhook URL)
- live log streaming
- artifact links (master report + readable HTML report)

## 7. Output structure

Each scan creates timestamped directories:

```text
recon_results/
├── subfinder_<timestamp>/
│   └── subdomains.txt
├── httpx_<timestamp>/
│   ├── live_hosts.txt
│   └── live_hosts.json
├── katana_<timestamp>/
│   ├── all_urls.txt
│   ├── readable_summary.html
│   └── *_crawl.txt
├── dirsearch_<timestamp>/
│   └── *_dirsearch.txt
├── nuclei_<timestamp>/
│   ├── nuclei_findings.txt
│   └── nuclei_findings.jsonl
├── diff_report_<timestamp>.txt
└── master_report_<timestamp>.txt
```

## 8. Examples

Single domain:

```bash
./webrecon -d example.com
```

Quick scan:

```bash
./webrecon -d example.com -p quick
```

Deep scan + custom severity:

```bash
./webrecon -d example.com -p deep -ns medium,high,critical
```

Domain list:

```bash
./webrecon -l domains.txt -o output_batch
```

Diff mode + alerts:

```bash
./webrecon -d example.com --diff --webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ
```

## 9. Troubleshooting

- **`httpx` option errors (like `No such option: -l`)**: you likely have the wrong `httpx` binary installed. Use ProjectDiscovery `httpx`.
- **Tool not found**: ensure binaries are in `PATH` (or under Go bin paths like `~/go/bin`).
- **No results**: target may block probes, DNS may fail, or no live hosts were discovered.

## 10. Legal notice

Run this tool only against assets you own or have explicit permission to test.
