# kql-lab

A self-contained lab for practising KQL (Kusto Query Language) against real Windows event logs.

```
Windows DC (WinLogBeat)
        │  Beats/5044
        ▼
   Logstash  ──►  relay  ──►  Kustainer (ADX)
                               NetDefaultDB.WindowsEvents
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux host (x86-64) | Ubuntu 22.04, Debian 12, or Fedora 39+ all work |
| Docker Engine ≥ 20.10 | `curl -fsSL https://get.docker.com | sh` |
| Docker Compose plugin | Ships with Docker Desktop; standalone: `apt install docker-compose-plugin` |
| `python3`, `curl` | Usually pre-installed |
| ≥ 6 GB free RAM | Kustainer alone uses ~3 GB at rest |
| Windows host / VM on the same network | The DC that ships event logs |

---

## Quick start (Linux host)

```bash
git clone <this-repo> kql-lab
cd kql-lab
chmod +x setup.sh teardown.sh
./setup.sh
```

`setup.sh` will:
1. Start **ADX (Kustainer)**, **Logstash**, and the **relay** via Docker Compose
2. Wait for Kustainer to become healthy
3. Create the `WindowsEvents` table, JSON ingestion mapping, and streaming policy
4. Send a test event end-to-end to confirm the pipeline works
5. Package `winlogbeat/` into `winlogbeat-dc.zip` for easy copy to the DC
6. Print the next steps

At the end you will see something like:

```
╔══════════════════════════════════════════════════════════════════╗
║  Setup Complete                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Kustainer REST API   http://localhost:8080                      ║
║  Logstash Beats port  <HOST_IP>:5044  (WinLogBeat target)       ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Connecting Kusto Explorer

1. Open **Kusto Explorer** (Windows) → **Add Connection**
2. Cluster URI: `http://<HOST_IP>:8080`
3. Database: `NetDefaultDB`
4. Run any query from `queries/`

---

## Windows DC setup

After `./setup.sh` completes, a file `winlogbeat-dc.zip` will be in the project
root. Copy it to the Windows DC and run as Administrator:

```powershell
# Expand-Archive on the DC, then:
Set-ExecutionPolicy Bypass -Scope Process -Force
cd winlogbeat
.\install-winlogbeat.ps1 -LogstashHost <HOST_IP>
```

The installer:
- Downloads and installs WinLogBeat 8.17
- Deploys `winlogbeat.yml` with your `HOST_IP` substituted in
- Applies all required audit policies (`auditpol`) and Group Policy registry keys
- Sets DCSync-detection SACLs on the domain root (for 4662)
- Registers and starts the WinLogBeat Windows service

After ~30 seconds, events should appear in Kustainer:

```kql
WindowsEvents | take 10
```

---

## Teardown

```bash
./teardown.sh            # stop containers, keep all data in ./data/
./teardown.sh --purge    # stop + wipe ./data/ (irreversible)
```

---

## Project layout

```
.
├── docker-compose.yml          # ADX + Logstash + relay
├── setup.sh                    # one-shot idempotent setup
├── teardown.sh                 # stop / purge
│
├── relay/
│   ├── Dockerfile
│   └── relay.py                # Logstash JSON → Kustainer .ingest inline
│
├── logstash/
│   ├── config/logstash.yml
│   └── pipeline/winlogbeat.conf
│
├── schemas/
│   └── windows_events.kql      # table + mapping + streaming policy DDL
│
├── queries/
│   ├── kerberoasting_detection.kql      # Tier1 burst + Tier2 sensitive SPN
│   └── kerberoasting_rc4_baseline.kql  # single-event RC4 detector (no thresholds)
│
└── winlogbeat/
    ├── winlogbeat.yml           # shipped to the DC; collector config
    └── install-winlogbeat.ps1  # DC installer + audit policy script
```

---

## Useful commands

```bash
# Live ingest rate
docker logs relay -f

# Events collected so far
curl -s -X POST http://localhost:8080/v1/rest/query \
  -H "Content-Type: application/json" \
  -d '{"db":"NetDefaultDB","csl":"WindowsEvents | count"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['Tables'][0]['Rows'][0][0])"

# Container health
docker stats --no-stream relay adx logstash

# ADX ingest failures
curl -s -X POST http://localhost:8080/v1/rest/mgmt \
  -H "Content-Type: application/json" \
  -d '{"db":"NetDefaultDB","csl":".show ingestion failures | count"}' | \
  python3 -c "import sys,json;d=json.load(sys.stdin);print(d['Tables'][0]['Rows'])"
```

---

## Re-ingesting missed events (after an outage)

If the relay was down and events were lost, wipe WinLogBeat's registry on the DC
to force a re-read from the `ignore_older: 72h` window:

```powershell
# On the DC as Administrator
Stop-Service winlogbeat
Remove-Item "C:\ProgramData\winlogbeat\data\registry\filebeat\log.json" -ErrorAction SilentlyContinue
Start-Service winlogbeat
```
