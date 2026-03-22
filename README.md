# kql-lab

A self-contained lab for practising KQL (Kusto Query Language) against real Windows event logs.
<img width="2163" height="652" alt="image" src="https://github.com/user-attachments/assets/56d66eda-6a34-4bf9-9fd8-7093adcb96d5" />

```
Windows DC (WinLogBeat)
        |  Beats/5044
        v
   Logstash  -->  relay  -->  Kustainer (ADX)
                               NetDefaultDB.WindowsEvents
```

---

## Quick Start -- Windows (Docker Desktop)

> **This is the easiest way to run the lab.** You just need a Windows 10/11
> machine with Docker Desktop installed and a Windows Server VM to act as the
> Domain Controller.  One script does everything.

### What you need before starting

| Thing | Why you need it |
|---|---|
| Windows 10 or 11 PC (x86-64, 6 GB+ RAM) | This is where Docker runs |
| [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) | Runs the lab containers |
| A Windows Server 2019/2022 VM on the same network | Becomes your Domain Controller and ships the event logs |

> **On your CPU:** Kustainer requires a CPU feature called **AVX2**.
> Physical machines made after ~2013 have it.  If you are running inside a VM,
> make sure CPU passthrough / hardware virtualisation is enabled in your
> hypervisor settings.

---

### Step 1 -- Install Docker Desktop (skip if you have it already)

1. Download Docker Desktop from **https://docs.docker.com/desktop/install/windows-install/**
2. Run the installer.  When it asks, tick **"Use WSL 2 instead of Hyper-V"** -- this is the default, just leave it ticked
3. Restart your computer when the installer tells you to
4. After restarting, open Docker Desktop from the Start menu and wait until the whale icon in the taskbar stops animating -- that means Docker is ready

---

### Step 2 -- Get the lab files

Open **PowerShell as Administrator**:
- Press the **Start** button
- Type `powershell`
- Right-click **"Windows PowerShell"** and choose **"Run as administrator"**
- Click **Yes** on the popup

Then paste this command and press Enter:

```powershell
git clone https://github.com/jagsblast/kql-lab.git "$env:USERPROFILE\kql-lab"
cd "$env:USERPROFILE\kql-lab"
```

> **Don't have git?** Download it from **https://git-scm.com/download/win**, install it, then close and re-open PowerShell and try again.

---

### Step 3 -- Tell the script where your DC is

Your Windows Server VM needs to already exist and be turned on.  You need its **IP address** -- open PowerShell on the VM and type `ipconfig` to find it.

Back in the `kql-lab` folder on your Windows machine, create a file called `.env`:

```powershell
# Replace 192.168.1.50 with your DC's actual IP address
'DC_HOST=192.168.1.50' | Set-Content .env
```

That's the only setting you need.  The script uses `Administrator` as the username by default.  If you want a different username add it too:

```powershell
Add-Content .env 'DC_USER=Administrator'
```

---

### Step 4 -- Run the setup script

Still in the same Administrator PowerShell window, run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

The script will:
1. Check your machine has everything it needs (AVX2, RAM, Docker)
2. Start the **Kustainer (ADX)**, **Logstash**, and **relay** containers
3. Create the database table and ingest pipeline automatically
4. Send a test event to make sure the pipeline works
5. Pop up a **password prompt** -- enter the Administrator password for your DC
6. Connect to the DC over PSRemoting and automatically:
   - Create the AD lab objects (OUs, users, SPNs, RC4 encryption, password policy)
   - Install and start WinLogBeat so event logs start flowing

The whole thing takes about **3-5 minutes** (plus a few minutes for WinLogBeat to download from the internet).

---

### Step 5 -- You're done!

When the script finishes you'll see something like:

```
==================================================================
  Setup Complete
==================================================================
  Kustainer REST API   http://localhost:8080
  Logstash Beats port  192.168.1.x:5044  (WinLogBeat target)
  Database             NetDefaultDB
  Table                WindowsEvents
==================================================================
  DC provisioned       AD objects + WinLogBeat installed [OK]
  Wait ~30 s then query Kustainer:
    WindowsEvents | take 10
==================================================================
```

After about 30 seconds, open your browser to **http://localhost:8080** and run:

```kql
WindowsEvents | take 10
```

You should see real Windows event logs appearing. If you see rows -- congratulations, the lab is working!

---

### Troubleshooting (Windows)

| Problem | Fix |
|---|---|
| `docker: command not found` | Open Docker Desktop from the Start menu and wait for it to finish loading |
| `Cannot connect to Docker Desktop` | Docker is still starting -- wait for the whale icon to stop animating in the taskbar |
| `AVX2 not available` | Enable CPU passthrough in your hypervisor, or run on a physical machine |
| DC password prompt pops up and fails | Make sure the DC IP is correct and WinRM is enabled -- see note below |
| `winrm quickconfig` error on DC | Run it in PowerShell as Administrator on the DC: `winrm quickconfig -q` |
| Setup worked but no events appear | Wait 30-60 seconds, then check `docker logs -f logstash` |

> **WinRM note:** If the DC has never had WinRM enabled, run this **on the DC** in an
> Administrator PowerShell before running `setup.ps1`:
> ```powershell
> winrm quickconfig -q
> ```

---

### To stop the lab

```powershell
.\teardown.ps1            # stop containers, keep all data
.\teardown.ps1 --purge    # stop + delete all ingested data
```

---
---

## Quick Start -- Linux host

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
5. Package `winlogbeat/` into `winlogbeat-dc.zip` for deploying to the DC

---

### DC setup (Linux path)

The Linux path uses **Ansible** to provision the DC remotely.

#### Prerequisites

| Requirement | Notes |
|---|---|
| Ubuntu 22.04 / Debian 12 / Fedora 39+ (x86-64) | |
| Docker Engine >= 20.10 | `curl -fsSL https://get.docker.com \| sh` |
| Docker Compose plugin | `apt install docker-compose-plugin` |
| >= 6 GB free RAM | Kustainer uses ~3 GB at rest |
| Windows Server 2019/2022 VM on the same network | |

#### Step A -- Enable WinRM on the DC

On the Windows Server VM, open **PowerShell as Administrator** and run:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
winrm set winrm/config/service/auth '@{Ntlm="true"}'
netsh advfirewall firewall add rule name="WinRM-HTTP" protocol=TCP dir=in localport=5985 action=allow
```

#### Step B -- Configure Ansible

Edit `ansible/inventory.ini` with the DC's IP:

```ini
[dc]
192.168.68.XXX   # <-- your Windows Server IP
```

Edit `ansible/group_vars/dc.yml` with the Administrator password:

```yaml
ansible_password: "YourAdminPassword"
```

#### Step C -- Install Ansible

```bash
pip3 install --user ansible pywinrm
ansible-galaxy collection install -r ansible/requirements.yml
```

#### Step D -- Run the playbook

```bash
ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml
```

The playbook handles everything automatically:

| Step | What happens |
|------|--------------|
| 1a-c | Rename computer, install AD DS/DNS roles, promote to DC, reboot |
| 2a | Create OU structure (`Lab / LabUsers / LabServices / LabComputers`) |
| 2b | Create lab user accounts (`attacker`, `svc_sql`, `labadmin`) |
| 2c | Set SPNs on `svc_sql` (Kerberoasting target) |
| 2d | Force RC4-only encryption on `svc_sql` (generates 0x17 tickets in event 4769) |
| 2e | Relax domain password policy |
| 2f-k | DNS forwarders, firewall rules, WinRM, disable IE ESC |
| 3a-b | Copy and run WinLogBeat installer on DC |

Takes about **5-10 minutes** (mostly the DC promotion reboot).

> **Manual fallback:** `setup.sh` creates `winlogbeat-dc.zip` in the project root.
> Copy it to the DC, extract it, then run as Administrator:
> ```powershell
> Set-ExecutionPolicy Bypass -Scope Process -Force
> .\install-winlogbeat.ps1 -LogstashHost <YOUR_LINUX_IP>
> ```

---

## Connecting Kusto Explorer

> Download: https://aka.ms/ke

1. Open **Kusto Explorer** (Windows) -> **Add Connection**
2. Cluster URI: `http://<HOST_IP>:8080`
3. Database: `NetDefaultDB`
4. Run any query from `queries/`

---

## Storage limits

By default `setup.sh` configures a **7-day retention policy** and a **5 GB cap** on `./data/`.
ADX automatically drops extents older than the retention window -- no manual cleanup needed.

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

## Teardown

**Windows (PowerShell):**
```powershell
.\teardown.ps1            # stop containers, keep all data
.\teardown.ps1 --purge    # stop + delete all ingested data
```

**Linux (bash):**
```bash
./teardown.sh            # stop containers, keep all data in ./data/
./teardown.sh --purge    # stop + wipe ./data/ (irreversible)
```

---

## Project layout

```
.
+-- docker-compose.yml          # ADX + Logstash + relay
+-- setup.ps1                   # Windows one-shot setup (Docker Desktop + DC provisioning)
+-- teardown.ps1                # Windows stop / purge
+-- setup.sh                    # Linux one-shot setup (Ansible DC provisioning)
+-- teardown.sh                 # Linux stop / purge
|
+-- ansible/
|   +-- setup-dc.yml            # playbook: promote DC + lab objects + WinLogBeat
|   +-- inventory.ini           # put your Windows Server IP here
|   +-- group_vars/dc.yml       # domain, passwords, users, SPNs -- all tunable
|   +-- requirements.yml        # ansible.windows + microsoft.ad collections
|
+-- relay/
|   +-- Dockerfile
|   +-- relay.py                # Logstash JSON -> Kustainer ingest
|
+-- logstash/
|   +-- config/logstash.yml
|   +-- pipeline/winlogbeat.conf
|
+-- schemas/
|   +-- windows_events.kql      # table + mapping + streaming policy DDL
|
+-- queries/
|   +-- kerberoasting_detection.kql      # Tier1 burst + Tier2 sensitive SPN
|   +-- kerberoasting_rc4_baseline.kql   # single-event RC4 detector
|   +-- bloodhound_ad_enum.kql           # BloodHound / LDAP enumeration
|   +-- threatref_enrich.kql             # IOC enrichment
|
+-- winlogbeat/
    +-- winlogbeat.yml           # collector config (deployed to DC)
    +-- install-winlogbeat.ps1   # DC installer + audit policy + SACLs
    +-- setup-dc.ps1             # DC promotion + AD lab objects (Phase1/Phase2)
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
