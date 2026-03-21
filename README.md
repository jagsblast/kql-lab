# kql-lab

A self-contained lab for practising KQL (Kusto Query Language) against real Windows event logs.
<img width="2163" height="652" alt="image" src="https://github.com/user-attachments/assets/56d66eda-6a34-4bf9-9fd8-7093adcb96d5" />

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

## Storage limits

By default `setup.sh` configures a **7-day retention policy** and a **5 GB cap** on `./data/`.
ADX automatically drops extents older than the retention window — no manual cleanup needed.

Configure both in `.env` (copy from `.env.example`):

```bash
cp .env.example .env
```

```ini
DATA_RETENTION_DAYS=7   # drop events older than N days
DATA_MAX_GB=5           # target cap for ./data/ directory
DATA_WARN_GB=2          # warn in setup.sh if free disk < N GB
DATA_MIN_FREE_GB=1      # abort setup.sh if free disk < N GB
```

**When `./data/` exceeds `DATA_MAX_GB`**, run `trim.sh`:

```bash
./trim.sh              # auto-reduce retention to fit under the cap
./trim.sh --check      # report size only, make no changes
./trim.sh --force 3    # force retention to exactly 3 days
```

`trim.sh` calculates a proportional new retention window, applies it to Kustainer,
and persists it back to `.env`. ADX purges the old extents in the background (~5 min).

**Cron** (check hourly, trim if needed):
```bash
0 * * * * /path/to/kql-lab/trim.sh >> /var/log/kql-lab-trim.log 2>&1
```

Check current disk usage:
```bash
du -sh ./data/
./trim.sh --check
```

---

## Quick start (Linux host)

```bash
git clone https://github.com/jagsblast/kql-lab.git kql-lab
cd kql-lab
chmod +x setup.sh teardown.sh
./setup.sh
```

`setup.sh` will:
1. Start **ADX (Kustainer)**, **Logstash**, and the **relay** via Docker Compose
2. Wait for Kustainer to become healthy
3. Create the `WindowsEvents` table, JSON ingestion mapping, and streaming policy
4. Send a test event end-to-end to confirm the pipeline works
5. Package `winlogbeat/` into `winlogbeat-dc.zip` (manual fallback)
6. **If Ansible is installed and `ansible/inventory.ini` has a DC IP set**, prompt you to run the full DC provisioning playbook right now — this promotes the DC, configures all lab objects, and installs WinLogBeat in one go
7. Print the summary

At the end you will see something like:

```
╔══════════════════════════════════════════════════════════════════╗
║  Setup Complete                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Kustainer REST API   http://localhost:8080                      ║
║  Logstash Beats port  <HOST_IP>:5044  (WinLogBeat target)        ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Connecting Kusto Explorer

> Download: https://aka.ms/ke

1. Open **Kusto Explorer** (Windows) → **Add Connection**
2. Cluster URI: `http://<HOST_IP>:8080`
3. Database: `NetDefaultDB`
4. Run any query from `queries/`

---

## Windows DC setup

This section walks you through creating a Windows Server VM, promoting it to a
Domain Controller, and wiring it up to the lab — all from your Linux machine.
No PowerShell knowledge required.

---

### Step 1 — Create a Windows Server VM

> **Important:** You need **Windows Server**, not a regular Windows desktop
> (Windows 10/11). Only Windows Server can be promoted to a Domain Controller.
> Windows Server 2019 or 2022 are both fine.

1. Create a new VM in your hypervisor (Proxmox, VMware, VirtualBox, Hyper-V, etc.)
2. Mount a **Windows Server 2019 or 2022** ISO and install it
   - Choose **"Server with Desktop Experience"** when the installer asks — this
     gives you a normal desktop instead of a command-line-only install
   - Set the **Administrator password** to something you'll remember — you'll
     need it in Step 3
3. Make sure the VM is on the **same network** as your Linux machine
   (the one running Docker / `setup.sh`)
4. Note down the VM's **IP address** — you'll need it shortly
   - You can find it in the VM's desktop: open PowerShell and type `ipconfig`

---

### Step 2 — Enable WinRM on the Windows Server VM

Ansible talks to Windows over **WinRM** (Windows Remote Management). You need
to enable it once on the VM before Ansible can do anything.

On the Windows Server VM, open **PowerShell as Administrator** (right-click the
Start menu → "Windows PowerShell (Admin)") and run:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
winrm set winrm/config/service/auth '@{Ntlm="true"}'
netsh advfirewall firewall add rule name="WinRM-HTTP" protocol=TCP dir=in localport=5985 action=allow
```

That's the only thing you need to do on the Windows VM. Everything else is
done from your Linux machine.

---

### Step 3 — Configure the Ansible inventory

Back on your Linux machine, open `ansible/inventory.ini` and replace the
placeholder IP with the Windows Server VM's actual IP address:

```ini
[dc]
192.168.68.XXX   # <-- put your Windows Server IP here
```

Then open `ansible/group_vars/dc.yml` and fill in the Administrator password
you set during the Windows install:

```yaml
ansible_password: "YourAdminPassword"   # <-- change this
```

Everything else in that file (domain name, user accounts, passwords) can be
left as-is for the lab.

---

### Step 4 — Install Ansible and its Windows modules

If you don't have Ansible installed yet:

```bash
pip3 install --user ansible pywinrm
```

Then install the required Ansible collections:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

---

### Step 5 — Run the playbook

You can either let `./setup.sh` run it for you (it will ask at the end), or
trigger it manually at any time:

```bash
ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml
```

The playbook runs three phases automatically:

| Step | What happens |
|------|--------------|
| 1a | Rename the computer to `Kql-lab-DC` and reboot if needed |
| 1b | Install the AD DS, DNS, and GPMC Windows features |
| 1c | Promote the server to Domain Controller (`insane.local`) and reboot |
| 2a | Create the OU structure (`Lab / LabUsers / LabServices / LabComputers`) |
| 2b | Create lab user accounts (`attacker`, `svc_sql`, `labadmin`) |
| 2c | Set SPNs on `svc_sql` (makes it a Kerberoasting target) |
| 2d | Force RC4-only encryption on `svc_sql` (generates 0x17 tickets in event 4769) |
| 2e | Relax the domain password policy (allows simple lab passwords) |
| 2f–g | Configure DNS forwarders + reverse zone |
| 2h–k | Open firewall rules, enable WinRM, disable IE ESC, disable domain firewall |
| 3a | Copy `install-winlogbeat.ps1` and `winlogbeat.yml` to the DC |
| 3b | Run the WinLogBeat installer — downloads, configures, and starts the service |

The whole run takes about **5–10 minutes** (most of that is the DC promotion
reboot). You can leave it running and come back — Ansible reconnects
automatically after the reboot.

When it finishes you'll see:

```
DC Lab Setup COMPLETE
Domain : insane.local (INSANE)
...
```

After ~30 seconds, events should be flowing into Kustainer:

```kql
WindowsEvents | take 10
```

---

### Step 6 — Done

If the Ansible playbook completed successfully, WinLogBeat is already installed
and running. You don't need to do anything else on the DC.

> **Manual fallback** (if you skipped Ansible or want to reinstall WinLogBeat
> by hand): `setup.sh` creates `winlogbeat-dc.zip` in the project root. Copy
> it to the DC, extract it, then run in an **Administrator** PowerShell:
>
> ```powershell
> Set-ExecutionPolicy Bypass -Scope Process -Force
> cd winlogbeat
> .\install-winlogbeat.ps1 -LogstashHost <YOUR_LINUX_IP>
> ```
>
> Replace `<YOUR_LINUX_IP>` with the IP of your Linux machine.

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
├── setup.sh                    # one-shot idempotent setup (offers Ansible DC provisioning)
├── teardown.sh                 # stop / purge
│
├── ansible/
│   ├── setup-dc.yml            # playbook: rename → promote DC → lab objects → WinLogBeat
│   ├── inventory.ini           # put your Windows Server IP here
│   ├── group_vars/dc.yml       # domain, passwords, users, SPNs — all tunable vars
│   └── requirements.yml        # ansible.windows + microsoft.ad collections
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
    ├── winlogbeat.yml           # collector config (deployed to DC by Ansible)
    ├── install-winlogbeat.ps1  # DC installer + audit policy script (run by Ansible)
    └── setup-dc.ps1            # PowerShell fallback (reference only)
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
---

## todo
Maybe a provisioning script to build the windows VM in Proxmox too
