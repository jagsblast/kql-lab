#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# load-threatref.sh — Load Windows Event Log threat reference into Kustainer
#
# Creates the ThreatReference lookup table and populates it from the
# Cybanetix Windows Event Log Threat Detection Reference (March 2026).
#
# The table is designed for lookup joins against WindowsEvents:
#
#   WindowsEvents
#   | lookup kind=leftouter ThreatReference
#       on $left.EventId == $right.EventId,
#          $left.Channel  == $right.LogSource
#
# Usage:
#   ./load-threatref.sh          — load/refresh reference data
#   ./load-threatref.sh --check  — verify row count only, no changes
#
# Re-run safely at any time — uses .set-or-replace (atomic, idempotent).
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADX_URL="http://localhost:8080"

[[ -f "$SCRIPT_DIR/.env" ]] && set -o allexport && source "$SCRIPT_DIR/.env" && set +o allexport

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[threatref]${NC} $*"; }
warn() { echo -e "${YELLOW}[threatref]${NC} $*"; }
fail() { echo -e "${RED}[threatref]${NC} $*" >&2; exit 1; }

CHECK_ONLY=false
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=true

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Windows Event Log Threat Reference → Kustainer${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""

command -v curl    >/dev/null 2>&1 || fail "curl not found"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"

curl -sf -X POST "${ADX_URL}/v1/rest/mgmt" \
    -H "Content-Type: application/json" \
    -d '{"db":"NetDefaultDB","csl":".show version"}' \
    -o /dev/null 2>/dev/null \
    || fail "Kustainer not reachable at ${ADX_URL} — is the stack running? (./setup.sh)"

if $CHECK_ONLY; then
    log "Check mode — verifying ThreatReference row count ..."
    python3 - <<'PYEOF'
import json, urllib.request, sys
def query(csl):
    body = json.dumps({"db":"NetDefaultDB","csl":csl}).encode()
    req = urllib.request.Request("http://localhost:8080/v1/rest/query",data=body,
        headers={"Content-Type":"application/json","Accept":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=30) as r:
        return json.loads(r.read())
try:
    d = query("ThreatReference | count")
    print(f"  ThreatReference row count: {d['Tables'][0]['Rows'][0][0]}")
except Exception as e:
    print(f"  Table not found or empty: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    exit 0
fi

log "Loading threat reference data ..."
python3 - <<'PYEOF'
import json, urllib.request, sys

BASE = "http://localhost:8080"
DB   = "NetDefaultDB"

def mgmt(csl, label=""):
    body = json.dumps({"db": DB, "csl": csl}).encode()
    req  = urllib.request.Request(f"{BASE}/v1/rest/mgmt", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            if label: print(f"  ✓  {label}")
            return result
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        print(f"  ✗  {label}: HTTP {e.code} — {msg[:400]}", file=sys.stderr)
        raise

# ── Schema ────────────────────────────────────────────────────────────────────
mgmt(""".create-merge table ThreatReference (
    LogSource     : string,
    EventId       : int,
    EventName     : string,
    Category      : string,
    SubCategory   : string,
    ThreatActions : string,
    MitreIds      : string,
    Priority      : string,
    CollectionTier: int
)""", "table  ThreatReference")

# ── Reference data ────────────────────────────────────────────────────────────
# Tuple: (LogSource, EventId, EventName, Category, SubCategory,
#         ThreatActions, MitreIds, Priority, CollectionTier)
EVENTS = [
    # ── Security: Log Tampering & Audit Policy ────────────────────────────────
    ("Security", 1100, "Event logging service shut down",
     "Defense Evasion", "Log Tampering",
     "Log suppression before attack; forced service kill; pre-clear activity",
     "T1562.002", "Critical", 1),
    ("Security", 1102, "Audit log cleared",
     "Defense Evasion", "Log Tampering",
     "Anti-forensics; post-compromise cleanup; attacker erasing lateral movement trail",
     "T1070.001", "Critical", 1),
    ("Security", 4616, "System time changed",
     "Defense Evasion", "Log Tampering",
     "Kerberos abuse prep (ticket window manipulation); log-timeline corruption",
     "T1070.006", "High", 1),
    ("Security", 4719, "System audit policy changed",
     "Defense Evasion", "Log Tampering",
     "Logging suppression before high-noise activity; defense evasion",
     "T1562.002", "Critical", 1),
    ("Security", 5038, "Code integrity violation - invalid image hash",
     "Defense Evasion", "Binary Integrity",
     "Tampered binary or unsigned image executing; BYOVD precursor",
     "T1553.002", "High", 1),

    # ── Security: Logon & Authentication ─────────────────────────────────────
    ("Security", 4624, "Successful logon",
     "Lateral Movement,Initial Access", "Logon",
     "Valid account use after compromise; lateral movement (type 3/9/10); Pass-the-Hash; RDP interactive logon; service/batch execution",
     "T1078,T1021,T1550.002", "Critical", 1),
    ("Security", 4625, "Failed logon",
     "Credential Access", "Logon",
     "Password spray; brute force; service account credential failure; account enumeration; RDP scanning",
     "T1110.001,T1110.003,T1078", "High", 1),
    ("Security", 4634, "Logoff",
     "Defense Evasion", "Logon",
     "Session windowing; short-lived admin sessions indicating tooling; stolen credential usage dwell time",
     "T1078", "Medium", 1),
    ("Security", 4647, "User-initiated logoff",
     "Defense Evasion", "Logon",
     "Operator covering tracks; logon-action-logoff pattern",
     "T1078", "Low", 1),
    ("Security", 4648, "Explicit credentials used (RunAs)",
     "Privilege Escalation,Lateral Movement", "Logon",
     "RunAs abuse; PsExec-style alternate credential authentication; lateral movement via explicit creds",
     "T1078,T1134.001", "High", 1),
    ("Security", 4672, "Special privileges assigned to new logon",
     "Privilege Escalation", "Logon",
     "Privileged admin logon confirmation; pivot point for privilege escalation chains",
     "T1078.002,T1134", "High", 1),
    ("Security", 4768, "Kerberos TGT requested",
     "Credential Access", "Kerberos",
     "AS-REP roasting baseline; Golden Ticket anomaly hunting; TGT volume from unusual hosts",
     "T1558.001,T1558.004", "High", 1),
    ("Security", 4769, "Kerberos TGS requested",
     "Credential Access", "Kerberos",
     "Kerberoasting (RC4/etype 0x17); SPN recon; Silver Ticket use; service ticket volume outliers",
     "T1558.003,T1550.003", "Critical", 1),
    ("Security", 4771, "Kerberos pre-auth failed",
     "Credential Access", "Kerberos",
     "Password spray against Kerberos; AS-REP roasting precursor; brute force",
     "T1110,T1558.004", "High", 1),
    ("Security", 4776, "NTLM authentication attempt",
     "Credential Access,Lateral Movement", "Authentication",
     "Pass-the-Hash; legacy auth detection; NTLM spray against SAM/AD",
     "T1550.002,T1110", "High", 1),
    ("Security", 4778, "Session reconnected",
     "Lateral Movement", "RDP",
     "RDP reconnect; session hijack; admin remote session tracking",
     "T1021.001", "Medium", 1),
    ("Security", 4779, "Session disconnected",
     "Lateral Movement", "RDP",
     "RDP session tracking; operator movement windowing",
     "T1021.001", "Low", 1),
    ("Security", 4964, "Special groups assigned to new logon",
     "Privilege Escalation", "Logon",
     "High-value account activity; privileged group tracking; escalation monitoring",
     "T1078.002", "High", 1),
    ("Security", 6272, "NPS/RADIUS access granted",
     "Initial Access", "Remote Access",
     "VPN abuse; valid credential remote access; authorized but anomalous remote access",
     "T1078,T1133", "Medium", 1),
    ("Security", 6273, "NPS/RADIUS access denied",
     "Credential Access", "Remote Access",
     "Remote access brute force; unauthorized VPN access attempt",
     "T1110,T1133", "Medium", 1),
    ("Security", 6274, "NPS/RADIUS request discarded",
     "Credential Access", "Remote Access",
     "Auth anomaly; MFA/policy failure; unauthorized network access attempt",
     "T1110,T1078,T1133", "Medium", 1),
    ("Security", 6276, "NPS/RADIUS user quarantined",
     "Initial Access", "Remote Access",
     "NAP/quarantine enforcement; policy violation on remote access",
     "T1133", "Medium", 1),
    ("Security", 6277, "NPS/RADIUS granted probationary access",
     "Initial Access", "Remote Access",
     "Probationary VPN access; policy exemption or enforcement context",
     "T1133", "Medium", 1),
    ("Security", 6279, "NPS/RADIUS account locked",
     "Credential Access", "Remote Access",
     "RADIUS account lockout from repeated failed auth (brute force indicator)",
     "T1110", "High", 1),
    ("Security", 6280, "NPS/RADIUS account unlocked",
     "Credential Access", "Remote Access",
     "RADIUS lockout recovery; admin responding to brute force or spray",
     "T1110", "Medium", 1),

    # ── Security: Account & Identity Lifecycle ────────────────────────────────
    ("Security", 4720, "User account created",
     "Persistence", "Account Creation",
     "Backdoor account creation; persistence via rogue local/domain account",
     "T1136.001,T1136.002", "High", 1),
    ("Security", 4722, "User account enabled",
     "Persistence", "Account Manipulation",
     "Dormant account re-enabled as backdoor; persistence reactivation",
     "T1098,T1078", "High", 1),
    ("Security", 4725, "User account disabled",
     "Impact", "Account Manipulation",
     "Admin sabotage; disruption; cleanup of temporary rogue account",
     "T1531", "Medium", 1),
    ("Security", 4726, "User account deleted",
     "Defense Evasion", "Account Manipulation",
     "Anti-forensics; rogue account removal post-use; admin sabotage",
     "T1070,T1531", "Medium", 1),
    ("Security", 4738, "User account changed",
     "Persistence,Defense Evasion", "Account Manipulation",
     "Password policy change; UAC flag manipulation; account attribute tampering",
     "T1098,T1484", "High", 1),
    ("Security", 4740, "Account locked out",
     "Credential Access", "Brute Force",
     "Password spray (distributed); brute force; broken service account creds; targeted lockout DoS",
     "T1110", "High", 1),
    ("Security", 4741, "Computer account created",
     "Persistence", "Account Creation",
     "Rogue machine account creation; computer account abuse for Kerberoasting or RBCD",
     "T1136.002,T1558.003", "High", 1),
    ("Security", 4742, "Computer account changed",
     "Persistence,Privilege Escalation", "Account Manipulation",
     "Computer account attribute abuse; RBCD tamper; SPN manipulation on machine account",
     "T1098,T1558.001", "High", 1),
    ("Security", 4743, "Computer account deleted",
     "Defense Evasion", "Account Manipulation",
     "Rogue machine account cleanup; computer account sabotage",
     "T1070,T1531", "Medium", 1),
    ("Security", 4765, "SID History added to account",
     "Privilege Escalation", "SIDHistory",
     "SIDHistory privilege escalation — allows account to inherit permissions of another SID",
     "T1134.005", "Critical", 1),
    ("Security", 4766, "Attempt to add SID History failed",
     "Privilege Escalation", "SIDHistory",
     "SIDHistory abuse attempt detected and failed",
     "T1134.005", "High", 1),
    ("Security", 4767, "User account unlocked",
     "Credential Access", "Account Manipulation",
     "Reactivation after brute force; admin responding to lockout attack",
     "T1078", "Medium", 1),
    ("Security", 4781, "Account name changed",
     "Defense Evasion,Persistence", "Account Manipulation",
     "Account masquerading; backdoor concealment; renaming to blend in with legitimate accounts",
     "T1036.005,T1098", "High", 1),
    ("Security", 4782, "Password hash accessed",
     "Credential Access", "Credential Dumping",
     "Credential access; identity tampering; requires platform-specific parsing",
     "T1003,T1552", "High", 1),
    ("Security", 4793, "Password policy API checked",
     "Discovery", "Reconnaissance",
     "Password policy recon; brute force planning; pre-attack infrastructure assessment",
     "T1201", "Medium", 1),

    # ── Security: Group & Privilege Changes ───────────────────────────────────
    ("Security", 4704, "User right assigned",
     "Privilege Escalation,Persistence", "Privilege Management",
     "Dangerous privilege grant (SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege); persistence via rights abuse",
     "T1098,T1134", "High", 1),
    ("Security", 4728, "Member added to global security group",
     "Privilege Escalation", "Group Management",
     "Domain Admin / privileged group escalation; high-value group membership change",
     "T1098.003", "Critical", 1),
    ("Security", 4731, "Security-enabled local group created",
     "Persistence,Discovery", "Group Management",
     "Hidden local group creation for persistent access; new privilege boundary",
     "T1069,T1098", "High", 1),
    ("Security", 4732, "Member added to local group",
     "Privilege Escalation", "Group Management",
     "Local admin escalation; backdoor group membership; local admin rights granted",
     "T1098", "High", 1),
    ("Security", 4733, "Member removed from group",
     "Impact,Defense Evasion", "Group Management",
     "Cleanup; role tampering; admin sabotage; removing competitor accounts from groups",
     "T1531", "Medium", 1),
    ("Security", 4735, "Security-enabled local group changed",
     "Defense Evasion,Persistence", "Group Management",
     "Group policy / delegation abuse; privilege model tampering",
     "T1484,T1098", "Medium", 1),
    ("Security", 4756, "Member added to universal security group",
     "Privilege Escalation", "Group Management",
     "Escalation via universal groups; cross-domain privilege gain",
     "T1098.003", "High", 1),

    # ── Security: Domain & Trust Changes ─────────────────────────────────────
    ("Security", 4706, "New domain trust created",
     "Privilege Escalation,Persistence", "Domain Trust",
     "Domain trust abuse; cross-domain movement; identity boundary weakening",
     "T1484.002", "High", 1),
    ("Security", 4713, "Kerberos policy changed",
     "Defense Evasion,Credential Access", "Kerberos",
     "Kerberos weakening; ticket lifetime extension for Golden Ticket longevity; RC4 re-enablement",
     "T1558.001,T1484", "High", 1),
    ("Security", 4714, "Encrypted data recovery policy changed",
     "Defense Evasion", "Policy Modification",
     "Domain security policy tampering; EFS recovery agent manipulation",
     "T1484", "High", 1),
    ("Security", 4715, "Audit policy on an object changed",
     "Defense Evasion", "Audit Evasion",
     "Object-level audit suppression; removing visibility from sensitive object access",
     "T1562.002", "High", 1),
    ("Security", 4716, "Trusted domain information modified",
     "Persistence,Privilege Escalation", "Domain Trust",
     "Trust abuse; cross-trust persistence; identity boundary tampering",
     "T1484.002", "High", 1),
    ("Security", 4717, "System security access granted to account",
     "Persistence", "Privilege Management",
     "Dangerous right grant; persistence via logon-as-service or batch rights",
     "T1098", "High", 1),

    # ── Security: Process Creation ────────────────────────────────────────────
    ("Security", 4688, "Process created",
     "Execution", "Process Creation",
     "LOLBIN abuse (rundll32, regsvr32, mshta, certutil, bitsadmin, wmic); malware execution; PowerShell encoded payloads; credential theft tooling; recon commands; lateral movement payloads",
     "T1059,T1218,T1003,T1105,T1027", "Critical", 1),

    # ── Security: Registry & Object Access ───────────────────────────────────
    ("Security", 4657, "Registry value modified",
     "Persistence,Defense Evasion", "Registry",
     "Persistence via run keys / services; Defender/security tooling config tampering; policy modification",
     "T1112,T1547.001,T1562.001", "High", 1),
    ("Security", 4663, "Object access attempted",
     "Credential Access,Collection", "Object Access",
     "LSASS/SAM dump staging; GPO/SYSVOL/policy access; sensitive file recon; share-staged payload access",
     "T1003,T1039,T1083", "High", 1),
    ("Security", 4670, "Permissions on object changed",
     "Defense Evasion,Persistence", "ACL Manipulation",
     "ACL abuse; privileged object control; delegation tamper; DACL modification",
     "T1222,T1484", "High", 1),

    # ── Security: Scheduled Tasks ─────────────────────────────────────────────
    ("Security", 4698, "Scheduled task created",
     "Persistence,Execution", "Scheduled Task",
     "Persistence; delayed payload execution; malware launcher; logon-trigger task",
     "T1053.005", "High", 1),
    ("Security", 4699, "Scheduled task deleted",
     "Defense Evasion", "Scheduled Task",
     "Post-exploitation cleanup; anti-forensics; temporary persistence removal",
     "T1070,T1053.005", "High", 1),
    ("Security", 4702, "Scheduled task updated",
     "Persistence", "Scheduled Task",
     "Persistence modification; payload swap; trigger change; privilege escalation via task edit",
     "T1053.005", "High", 1),

    # ── Security: AD Directory Services ──────────────────────────────────────
    ("Security", 4662, "AD object operation",
     "Credential Access,Defense Evasion", "AD DS",
     "Directory object access; sensitive LDAP operations; DCSync prep; ACE abuse — fires when replication extended rights exercised",
     "T1003.006,T1484,T1222", "High", 1),
    ("Security", 5136, "Directory object attribute modified",
     "Persistence,Credential Access,Privilege Escalation", "AD DS",
     "Shadow Credentials (msDS-KeyCredentialLink); SPN write for Kerberoasting (servicePrincipalName); RBCD abuse (msDS-AllowedToActOnBehalfOfOtherIdentity); ACL tamper (nTSecurityDescriptor); membership changes",
     "T1556.006,T1558.003,T1484,T1098", "Critical", 1),
    ("Security", 5137, "Directory object created",
     "Persistence", "AD DS",
     "Rogue user/computer/container object; malicious GPO-linked objects; persistence infrastructure",
     "T1136.002,T1484.001", "High", 1),
    ("Security", 5138, "Directory object undeleted",
     "Persistence,Defense Evasion", "AD DS",
     "Tombstone resurrection for persistence recovery; hidden object restoration",
     "T1098,T1070", "High", 1),
    ("Security", 5139, "Directory object moved",
     "Defense Evasion,Privilege Escalation", "AD DS",
     "OU scope or delegation boundary abuse; stealthy admin reshuffling",
     "T1484,T1222", "Medium", 1),
    ("Security", 5141, "Directory object deleted",
     "Defense Evasion", "AD DS",
     "Anti-forensics; GPO/object sabotage; removal of malicious objects post-use",
     "T1070,T1484", "Medium", 1),

    # ── Security: Network Share Access ───────────────────────────────────────
    ("Security", 5140, "Network share object accessed",
     "Lateral Movement,Collection", "Network Share",
     "SMB lateral movement; admin share recon; SYSVOL/NETLOGON access",
     "T1021.002,T1135,T1039", "High", 1),
    ("Security", 5144, "Network share object deleted",
     "Defense Evasion", "Network Share",
     "Anti-forensics via share; file deletion cleanup",
     "T1070,T1039", "Medium", 1),
    ("Security", 5145, "Network share object checked (file-level ACL check)",
     "Lateral Movement,Collection", "Network Share",
     "Payload staging over SMB (ADMIN$, C$); PsExec-like tool behavior; data collection; exfil staging; mass file access",
     "T1021.002,T1039,T1074", "High", 1),

    # ── Security: Credential Manager ─────────────────────────────────────────
    ("Security", 5376, "Credential Manager credentials backed up",
     "Credential Access", "Credential Manager",
     "Credential theft; DPAPI-stored credential extraction",
     "T1555.004", "High", 1),
    ("Security", 5377, "Credential Manager credentials restored",
     "Credential Access", "Credential Manager",
     "Credential theft follow-on; saved credential abuse",
     "T1555.004", "High", 1),

    # ── Security: Netlogon / Secure Channel ───────────────────────────────────
    ("Security", 5829, "Netlogon allowed vulnerable Netlogon secure channel",
     "Lateral Movement,Credential Access", "Netlogon",
     "Zerologon/CVE-2020-1472 context; legacy machine using vulnerable Netlogon",
     "T1557,T1003", "High", 1),
    ("Security", 5830, "Netlogon allowed vulnerable Netlogon secure channel (domain policy)",
     "Lateral Movement,Credential Access", "Netlogon",
     "Vulnerable Netlogon allowed by domain policy; downgrade risk",
     "T1557,T1484", "High", 1),
    ("Security", 5831, "Netlogon allowed vulnerable Netlogon secure channel (machine policy)",
     "Lateral Movement,Credential Access", "Netlogon",
     "Vulnerable Netlogon allowed by machine policy exemption",
     "T1557", "High", 1),

    # ── Security: AD CS / Certificate Services ────────────────────────────────
    ("Security", 4880, "CA service started",
     "Privilege Escalation", "AD CS",
     "CA state change context; CA restart after configuration tampering",
     "T1649", "Medium", 1),
    ("Security", 4881, "CA service stopped",
     "Impact,Privilege Escalation", "AD CS",
     "CA disruption; denial-of-certificate; forced CA restart",
     "T1489,T1649", "High", 1),
    ("Security", 4882, "CA security permissions changed",
     "Privilege Escalation,Persistence", "AD CS",
     "CA ACL abuse; template control takeover; ESC-path enablement",
     "T1649,T1484", "Critical", 1),
    ("Security", 4885, "CA audit filter changed",
     "Defense Evasion", "AD CS",
     "Certificate audit suppression before ESC abuse",
     "T1562.002,T1649", "High", 1),
    ("Security", 4886, "Certificate requested",
     "Credential Access,Privilege Escalation", "AD CS",
     "ESC path activity; rogue cert request; SAN abuse; template abuse",
     "T1649", "High", 1),
    ("Security", 4887, "Certificate issued",
     "Credential Access,Privilege Escalation", "AD CS",
     "Confirming ESC / rogue enrollment success; shadow credential cert now active",
     "T1649", "Critical", 1),
    ("Security", 4888, "Certificate request denied",
     "Credential Access", "AD CS",
     "Failed ESC attempt; brute-force template abuse",
     "T1649", "Medium", 1),
    ("Security", 4890, "CA settings changed",
     "Persistence,Defense Evasion", "AD CS",
     "CA configuration tampering; may enable ESC paths or weaken PKI",
     "T1649,T1484", "High", 1),
    ("Security", 4891, "CA config entry changed",
     "Persistence", "AD CS",
     "CA tamper detail; follow-on to 4890",
     "T1649", "High", 1),
    ("Security", 4892, "CA key set changed",
     "Credential Access", "AD CS",
     "Crypto material tamper; key extraction; CA key abuse",
     "T1649,T1552", "Critical", 1),
    ("Security", 4896, "Certificate revoked",
     "Defense Evasion", "AD CS",
     "Covering tracks; attacker revoking evidence cert",
     "T1070", "Medium", 1),
    ("Security", 4897, "Role Separation enabled",
     "Defense Evasion", "AD CS",
     "CA config change; defense tamper via role separation modification",
     "T1649", "Medium", 1),
    ("Security", 4898, "CA policy module loaded",
     "Execution", "AD CS",
     "CA code execution / DLL load into CA process",
     "T1649", "High", 1),
    ("Security", 4899, "CA template updated",
     "Persistence,Privilege Escalation", "AD CS",
     "ESC setup; vulnerable template introduction enabling cert-based privesc",
     "T1649", "Critical", 1),
    ("Security", 4900, "CA template security updated",
     "Privilege Escalation,Persistence", "AD CS",
     "Template ACL change enabling template abuse (ESC4/ESC7 patterns)",
     "T1649", "Critical", 1),

    # ── System Event Log ──────────────────────────────────────────────────────
    ("System", 6, "Driver loaded",
     "Persistence,Privilege Escalation", "Driver",
     "BYOVD / malicious driver install context; kernel-level rootkit deployment",
     "T1014,T1543", "High", 1),
    ("System", 7000, "Service failed to start",
     "Persistence", "Service",
     "Broken malware service; broken persistence tooling after patch or reboot",
     "T1543.003", "Medium", 1),
    ("System", 7022, "Service hung",
     "Impact,Defense Evasion", "Service",
     "Security service targeted kill; malware-caused service instability; AV/EDR crash",
     "T1489,T1562.001", "High", 1),
    ("System", 7023, "Service terminated with error",
     "Impact,Defense Evasion", "Service",
     "Security service targeted kill; malware-caused service instability",
     "T1489,T1562.001", "High", 1),
    ("System", 7024, "Service terminated with specific error",
     "Impact,Defense Evasion", "Service",
     "AV/EDR crash; security service instability; possible attacker-induced kill",
     "T1489,T1562.001", "High", 1),
    ("System", 7026, "Boot-start or system-start driver failed to load",
     "Impact,Defense Evasion", "Driver",
     "Security driver targeted kill; malware-caused driver instability",
     "T1489,T1562.001", "High", 1),
    ("System", 7031, "Service crashed unexpectedly",
     "Impact,Defense Evasion", "Service",
     "AV/EDR/security service crash (may be attacker-induced); malware service instability",
     "T1489,T1562.001", "High", 1),
    ("System", 7032, "Service recovery action performed",
     "Persistence", "Service",
     "Auto-recovery from malware-caused crash; service restart after attacker kill",
     "T1489,T1562.001", "Medium", 1),
    ("System", 7034, "Service terminated unexpectedly",
     "Impact,Defense Evasion", "Service",
     "AV/EDR/security service crash; malware service instability",
     "T1489,T1562.001", "High", 1),
    ("System", 7045, "New service installed",
     "Persistence,Execution", "Service",
     "Service-based persistence; PsExec remote execution; malware service deployment; BYOVD helper service",
     "T1543.003,T1569.002", "Critical", 1),
    ("System", 1074, "User or process initiated shutdown/reboot",
     "Impact,Persistence", "System",
     "Forced reboot to activate persistence; reboot after security tool disablement; post-compromise system restart",
     "T1529,T1053", "Medium", 3),

    # ── Application Event Log ─────────────────────────────────────────────────
    ("Application", 1022, "MSI product installed",
     "Execution", "Software Install",
     "Unauthorized software install; malware installer; post-compromise tooling deployment",
     "T1072,T1204", "Medium", 3),
    ("Application", 1033, "MSI product removed",
     "Defense Evasion", "Software Install",
     "Tool removal; post-exploitation cleanup; anti-forensics",
     "T1072", "Medium", 3),

    # ── Sysmon Operational ────────────────────────────────────────────────────
    ("Microsoft-Windows-Sysmon/Operational", 1, "Process created",
     "Execution", "Process Creation",
     "LOLBIN abuse; malware execution; suspicious parent-child chains; encoded PowerShell; credential tooling; recon",
     "T1059,T1218,T1003,T1027", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 2, "File creation time changed",
     "Defense Evasion", "Timestomping",
     "Timestomping / anti-forensics; covering artifact timestamps",
     "T1070.006", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 3, "Network connection",
     "Command and Control,Lateral Movement", "Network",
     "C2 beaconing; reverse shells from PowerShell/cmd/LOLBINs; internal recon; lateral movement",
     "T1071,T1021,T1105", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 5, "Process terminated",
     "Execution", "Process",
     "Short-lived processes; tool execution watermarking; process lifetime analysis",
     "", "Low", 1),
    ("Microsoft-Windows-Sysmon/Operational", 6, "Driver loaded",
     "Persistence,Privilege Escalation", "Driver",
     "Unsigned/suspicious driver; BYOVD; rootkit deployment",
     "T1014,T1068,T1543", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 7, "Image (DLL) loaded",
     "Defense Evasion,Persistence", "DLL",
     "Unsigned DLL loads into high-value processes; DLL sideload; reflective loading",
     "T1574.001,T1574.002", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 8, "Remote thread created",
     "Defense Evasion,Privilege Escalation", "Process Injection",
     "Process injection into LSASS, browsers, AV/EDR, Winlogon; shellcode injection",
     "T1055", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 9, "Raw disk access",
     "Credential Access", "Credential Dumping",
     "NTDS.dit extraction; VSS-bypass for direct disk reads; raw credential file access",
     "T1003.003", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 10, "Process access (OpenProcess)",
     "Credential Access", "Credential Dumping",
     "LSASS handle acquisition for credential dumping; Mimikatz-style access patterns",
     "T1003.001", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 11, "File created",
     "Execution,Persistence", "File System",
     "Tool/payload drops; script writes; LoLBin staging; implant placement",
     "T1105,T1027", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 12, "Registry object added/deleted",
     "Persistence,Defense Evasion", "Registry",
     "Run key persistence; service key creation; COM hijack; IFEO debug key manipulation",
     "T1547.001,T1543,T1546.011", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 13, "Registry value set",
     "Persistence,Defense Evasion", "Registry",
     "Persistence via registry; Defender config tamper; security policy change via registry",
     "T1112,T1547.001,T1562", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 14, "Registry object renamed",
     "Defense Evasion,Persistence", "Registry",
     "Registry-based control flow hijack; IFEO abuse; key rename for persistence",
     "T1546.012", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 15, "File stream created (ADS)",
     "Defense Evasion", "File System",
     "Alternate data stream abuse; payload hiding in NTFS ADS",
     "T1564.004", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 17, "Named pipe created",
     "Lateral Movement,Command and Control", "Named Pipe",
     "PsExec-style lateral movement; Cobalt Strike/Metasploit named pipe C2 channel",
     "T1021.002,T1071", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 18, "Named pipe connected",
     "Lateral Movement,Command and Control", "Named Pipe",
     "Lateral movement tool activity; C2 pipe connection from implant",
     "T1021.002", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 19, "WMI event filter created",
     "Persistence,Execution", "WMI",
     "Permanent WMI event subscription persistence — filter creation",
     "T1546.003", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 20, "WMI event consumer created",
     "Persistence,Execution", "WMI",
     "Permanent WMI event subscription — consumer creation (specifies what to execute)",
     "T1546.003", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 21, "WMI consumer binding created",
     "Persistence,Execution", "WMI",
     "WMI filter-to-consumer binding completing persistent subscription (all 3 = confirmed persistence)",
     "T1546.003", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 22, "DNS query",
     "Command and Control,Discovery", "DNS",
     "C2 domain lookups; DGA behavior; suspicious TXT/MX queries; beaconing cadence analysis",
     "T1071.004,T1568", "High", 1),
    ("Microsoft-Windows-Sysmon/Operational", 23, "File deleted",
     "Defense Evasion", "File System",
     "Anti-forensics; payload cleanup; tool removal post-use",
     "T1070.004", "Medium", 1),
    ("Microsoft-Windows-Sysmon/Operational", 24, "Clipboard change",
     "Collection", "Clipboard",
     "Credential harvesting via clipboard; data interception by malware",
     "T1115", "Medium", 1),
    ("Microsoft-Windows-Sysmon/Operational", 25, "Process tampered (Hollowing)",
     "Defense Evasion", "Process Injection",
     "Process hollowing / process doppelganging; memory-resident implant",
     "T1055.012", "Critical", 1),
    ("Microsoft-Windows-Sysmon/Operational", 26, "File delete logged",
     "Defense Evasion", "File System",
     "Tooling cleanup; file deletion tracking with archive copy",
     "T1070.004", "Medium", 1),

    # ── PowerShell Classic ────────────────────────────────────────────────────
    ("Windows PowerShell", 169, "Engine lifecycle",
     "Execution", "PowerShell",
     "PowerShell engine start/stop tracking; session boundary",
     "T1059.001", "Low", 1),
    ("Windows PowerShell", 800, "Pipeline execution details",
     "Execution", "PowerShell",
     "Basic cmdlet/pipeline visibility; PowerShell v2-style activity without script block logging",
     "T1059.001", "Medium", 1),

    # ── PowerShell Operational ────────────────────────────────────────────────
    ("Microsoft-Windows-PowerShell/Operational", 4103, "Module logging",
     "Execution,Defense Evasion", "PowerShell",
     "AD cmdlet abuse (Get-ADUser, Set-ADUser); Defender tamper cmdlets (Set-MpPreference); WMI/CIM cmdlets; cert management",
     "T1059.001,T1562.001,T1053.005,T1484", "High", 1),
    ("Microsoft-Windows-PowerShell/Operational", 4104, "Script block logging",
     "Execution,Defense Evasion,Credential Access", "PowerShell",
     "Encoded payloads; IEX/Invoke-Expression; download cradles (DownloadString, WebClient); AMSI bypass (AmsiUtils); reflection/shellcode loaders; C2 framework tradecraft (Empire, Cobalt Strike, Nishang)",
     "T1059.001,T1027,T1140,T1562.001", "Critical", 1),
    ("Microsoft-Windows-PowerShell/Operational", 4105, "Script block start",
     "Execution", "PowerShell",
     "Long-running PowerShell pipeline tracking; complex script start boundary",
     "T1059.001", "Low", 1),
    ("Microsoft-Windows-PowerShell/Operational", 4106, "Script block end",
     "Execution", "PowerShell",
     "Pipeline boundary; automation chain windowing; script completion",
     "T1059.001", "Low", 1),
    ("Microsoft-Windows-PowerShell/Operational", 8193, "PSSession created",
     "Lateral Movement", "PowerShell Remoting",
     "Remote PowerShell session creation (WinRM); lateral movement via PSRemoting",
     "T1021.006,T1059.001", "High", 1),
    ("Microsoft-Windows-PowerShell/Operational", 8194, "PSSession connected",
     "Lateral Movement", "PowerShell Remoting",
     "Remote PowerShell session connection; lateral movement via PSRemoting",
     "T1021.006,T1059.001", "High", 1),
    ("Microsoft-Windows-PowerShell/Operational", 8197, "PSSession closed",
     "Lateral Movement", "PowerShell Remoting",
     "Remote PowerShell session closed; session duration and operator tracking",
     "T1021.006,T1059.001", "Medium", 1),
    ("Microsoft-Windows-PowerShell/Operational", 40961, "PowerShell console host start",
     "Execution", "PowerShell",
     "PowerShell engine lifecycle; session duration analysis; interactive vs automated session",
     "T1059.001", "Medium", 1),
    ("Microsoft-Windows-PowerShell/Operational", 40962, "PowerShell console host stop",
     "Execution", "PowerShell",
     "PowerShell engine stop; session duration analysis",
     "T1059.001", "Medium", 1),
    ("Microsoft-Windows-PowerShell/Operational", 53504, "PowerShell named pipe IPC",
     "Command and Control,Execution", "PowerShell",
     "Inter-process PowerShell communication via named pipe; C2 channel context",
     "T1071,T1059.001", "Medium", 1),

    # ── AppLocker: EXE and DLL ────────────────────────────────────────────────
    ("Microsoft-Windows-AppLocker/EXE and DLL", 8002, "Exe/DLL allowed",
     "Execution", "AppLocker",
     "Execution allowed — baseline/near-miss audit tracing; high value from temp/appdata paths",
     "T1218,T1059", "Low", 1),
    ("Microsoft-Windows-AppLocker/EXE and DLL", 8003, "Exe/DLL audit block (would have been blocked)",
     "Execution,Defense Evasion", "AppLocker",
     "Near-miss: tooling or malware that WOULD be blocked — extremely high value during tuning",
     "T1218,T1059", "High", 1),
    ("Microsoft-Windows-AppLocker/EXE and DLL", 8004, "Exe/DLL blocked",
     "Execution,Defense Evasion", "AppLocker",
     "Confirmed block: malware or LOLBIN execution attempted from disallowed path",
     "T1218,T1204", "High", 1),

    # ── AppLocker: MSI and Script ─────────────────────────────────────────────
    ("Microsoft-Windows-AppLocker/MSI and Script", 8005, "Script/MSI allowed",
     "Execution", "AppLocker",
     "Script execution audit baseline; high value from temp/download paths",
     "T1059,T1204", "Low", 1),
    ("Microsoft-Windows-AppLocker/MSI and Script", 8006, "Script/MSI audit block (would have been blocked)",
     "Execution,Defense Evasion", "AppLocker",
     "Near-miss: PS/VBS/JS or installer payload nearly stopped by policy",
     "T1059,T1204", "High", 1),
    ("Microsoft-Windows-AppLocker/MSI and Script", 8007, "Script/MSI blocked",
     "Execution,Defense Evasion", "AppLocker",
     "Script-based initial payload block; PS/VBS/JS/MSI execution stopped",
     "T1059,T1204", "High", 1),

    # ── AppLocker: Packaged App ───────────────────────────────────────────────
    ("Microsoft-Windows-AppLocker/Packaged app-Execution", 8022, "Packaged app execution blocked",
     "Execution", "AppLocker",
     "Unapproved packaged app execution attempt blocked",
     "T1072", "High", 1),
    ("Microsoft-Windows-AppLocker/Packaged app-Execution", 8023, "Packaged app deployment audit block",
     "Execution", "AppLocker",
     "App control bypass attempt via packaged app deployment",
     "T1072", "High", 1),
    ("Microsoft-Windows-AppLocker/Packaged app-Execution", 8025, "Packaged app deployment blocked",
     "Execution", "AppLocker",
     "Unapproved packaged app deployment blocked by policy",
     "T1072", "High", 1),

    # ── WMI-Activity Operational ──────────────────────────────────────────────
    ("Microsoft-Windows-WMI-Activity/Operational", 5857, "WMI activity started",
     "Execution,Lateral Movement", "WMI",
     "Remote WMI execution; process launch via WMI (Win32_Process.Create); lateral movement",
     "T1047", "High", 1),
    ("Microsoft-Windows-WMI-Activity/Operational", 5858, "WMI query failed",
     "Discovery", "WMI",
     "Failed WMI recon probes; high-failure-rate remote queries indicating host scanning",
     "T1047,T1018", "Medium", 1),
    ("Microsoft-Windows-WMI-Activity/Operational", 5859, "WMI event filter created",
     "Persistence,Execution", "WMI",
     "Permanent WMI event subscription persistence — filter creation stage",
     "T1546.003", "Critical", 1),
    ("Microsoft-Windows-WMI-Activity/Operational", 5860, "WMI event consumer created",
     "Persistence,Execution", "WMI",
     "Permanent WMI event subscription — consumer creation stage",
     "T1546.003", "Critical", 1),
    ("Microsoft-Windows-WMI-Activity/Operational", 5861, "WMI consumer binding created",
     "Persistence,Execution", "WMI",
     "WMI filter-to-consumer binding completing persistent subscription; all 3 events (5859+5860+5861) = confirmed persistence",
     "T1546.003", "Critical", 1),

    # ── NTLM Operational ──────────────────────────────────────────────────────
    ("Microsoft-Windows-NTLM/Operational", 8001, "NTLM pass-through auth",
     "Credential Access,Lateral Movement", "NTLM",
     "NTLM where Kerberos expected; relay precondition; legacy application forced NTLM; privileged account using NTLM",
     "T1550.002,T1187", "High", 2),
    ("Microsoft-Windows-NTLM/Operational", 8002, "NTLM blocked",
     "Defense Evasion,Credential Access", "NTLM",
     "NTLM restriction enforcement triggered; attempted downgrade to NTLM detected and blocked",
     "T1550.002", "Medium", 2),
    ("Microsoft-Windows-NTLM/Operational", 8003, "NTLM blocked (domain)",
     "Credential Access", "NTLM",
     "NTLM auth attempted to domain when restricted at domain level",
     "T1550.002", "High", 2),
    ("Microsoft-Windows-NTLM/Operational", 8004, "NTLM server blocked",
     "Credential Access", "NTLM",
     "Inbound NTLM blocked on server side; NTLM restriction enforcement",
     "T1550.002", "High", 2),

    # ── DNS Client Operational ────────────────────────────────────────────────
    ("Microsoft-Windows-DNS-Client/Operational", 3008, "DNS query failed",
     "Command and Control,Discovery", "DNS",
     "Malware C2 failed lookups; DGA beaconing misses; recon of non-existent hosts",
     "T1071.004,T1568", "Medium", 2),
    ("Microsoft-Windows-DNS-Client/Operational", 3020, "DNS query",
     "Command and Control,Discovery", "DNS",
     "Outbound DNS from process context; beaconing pattern; C2 domain lookups; DGA detection",
     "T1071.004", "Medium", 2),

    # ── Code Integrity Operational ────────────────────────────────────────────
    ("Microsoft-Windows-CodeIntegrity/Operational", 3001, "Unsigned driver rejected",
     "Defense Evasion,Privilege Escalation", "BYOVD",
     "BYOVD attempt stopped; rootkit deployment blocked by kernel code integrity",
     "T1014,T1068", "Critical", 1),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3002, "Unsigned kernel binary",
     "Defense Evasion", "Binary Integrity",
     "Tampered kernel component; rootkit binary detected",
     "T1014", "Critical", 1),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3003, "Unsigned DLL load",
     "Defense Evasion,Persistence", "Binary Integrity",
     "Malicious DLL injection; hijack attempt; unsigned plugin load into protected process",
     "T1574", "High", 1),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3004, "Unsigned PE rejected",
     "Defense Evasion", "Binary Integrity",
     "Tampered executable rejected; integrity check failure on PE load",
     "T1553", "High", 1),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3010, "WDAC/CSP policy violation",
     "Defense Evasion,Execution", "App Control",
     "Windows Defender Application Control policy bypass; unauthorized execution attempt",
     "T1218", "High", 1),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3023, "Boot-critical driver blocked",
     "Persistence,Privilege Escalation", "BYOVD",
     "BYOVD via boot driver path; malicious driver attempting kernel persistence at boot",
     "T1014,T1068", "Critical", 1),

    # ── Task Scheduler Operational ────────────────────────────────────────────
    ("Microsoft-Windows-TaskScheduler/Operational", 106, "Task registered",
     "Persistence,Execution", "Scheduled Task",
     "Task persistence creation; delayed payload launch; malicious scheduled task registered",
     "T1053.005", "High", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 107, "Task triggered",
     "Execution", "Scheduled Task",
     "Execution of registered scheduled task; malicious task fired",
     "T1053.005", "Medium", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 110, "Task launched",
     "Execution", "Scheduled Task",
     "Task action fired with command line context; execution logging",
     "T1053.005", "Medium", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 140, "Task updated",
     "Persistence", "Scheduled Task",
     "Persistence modification; payload swap; trigger change; privilege escalation via task edit",
     "T1053.005", "High", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 141, "Task deleted",
     "Defense Evasion", "Scheduled Task",
     "Post-exploitation cleanup; task persistence removed to cover tracks",
     "T1070,T1053.005", "High", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 142, "Task disabled",
     "Defense Evasion", "Scheduled Task",
     "Disruption; anti-forensics; attacker disabling legitimate security tasks",
     "T1562,T1053.005", "Medium", 2),
    ("Microsoft-Windows-TaskScheduler/Operational", 200, "Task action launched",
     "Execution", "Scheduled Task",
     "Full command line of task execution; highest-fidelity task execution event",
     "T1053.005", "High", 2),

    # ── Certificate Lifecycle (User) ───────────────────────────────────────────
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1001, "Certificate requested",
     "Credential Access,Privilege Escalation", "Certificate",
     "ESC / AD CS abuse attempt; Shadow Credential follow-on cert request",
     "T1649", "High", 2),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1002, "Certificate enrollment succeeded",
     "Credential Access,Privilege Escalation", "Certificate",
     "Certificate enrollment success; shadow credential cert now active for PKINIT auth",
     "T1649", "High", 2),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1003, "Certificate enrollment failed",
     "Credential Access", "Certificate",
     "Failed ESC attempt; investigation trigger for repeated certificate request failures",
     "T1649", "Medium", 2),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1004, "Certificate renewed",
     "Persistence", "Certificate",
     "Persistent cert-based auth; PKI backdoor certificate renewal",
     "T1649", "Medium", 2),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1006, "Certificate auto-enrolled",
     "Persistence", "Certificate",
     "Auto-enroll abuse; template-based certificate persistence",
     "T1649", "Medium", 2),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational", 1007, "Certificate deleted",
     "Defense Evasion", "Certificate",
     "Anti-forensics; evidence cert removed; shadow credential artifact cleanup",
     "T1070,T1649", "Low", 2),

    # ── Windows Firewall ──────────────────────────────────────────────────────
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2004, "Firewall rule added",
     "Defense Evasion", "Firewall",
     "New inbound allow rule exposing port (SMB 445, WinRM 5985/5986, RDP 3389); attacker-created rule for persistent access",
     "T1562.004", "High", 3),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2005, "Firewall rule changed",
     "Defense Evasion", "Firewall",
     "Broadening existing allow rule; removing source IP restrictions from C2 rule",
     "T1562.004", "High", 3),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2006, "Firewall rule deleted",
     "Defense Evasion", "Firewall",
     "Removing block or restriction rule; re-enabling blocked port for attack",
     "T1562.004", "High", 3),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2009, "Firewall rule parse error",
     "Defense Evasion", "Firewall",
     "Tampered or corrupt firewall configuration",
     "T1562.004", "Medium", 3),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2033, "All firewall rules flushed",
     "Defense Evasion", "Firewall",
     "Complete firewall disablement; all rules deleted in one operation",
     "T1562.004", "Critical", 3),

    # ── LSA Operational ───────────────────────────────────────────────────────
    ("Microsoft-Windows-LSA/Operational", 300, "LSA/SSPI event",
     "Credential Access,Defense Evasion", "LSA",
     "LSA or auth package anomaly; security subsystem issue; potential SSP/memssp injection via Mimikatz",
     "T1547.005,T1003", "High", 2),

    # ── CAPI2 Operational ─────────────────────────────────────────────────────
    ("Microsoft-Windows-CAPI2/Operational", 11, "Certificate chain build",
     "Credential Access,Privilege Escalation", "CAPI2",
     "Certificate validation during auth; PKI abuse investigation context",
     "T1649,T1550.003", "Medium", 2),
    ("Microsoft-Windows-CAPI2/Operational", 70, "Certificate private key operation",
     "Credential Access", "CAPI2",
     "Private key access; credential extraction involving certificate material",
     "T1552.004,T1649", "High", 2),
    ("Microsoft-Windows-CAPI2/Operational", 90, "X509 object operation",
     "Credential Access,Privilege Escalation", "CAPI2",
     "Cert chain building; shadow credential cert use; PKINIT auth context for cert-based logon",
     "T1649,T1550.003", "High", 2),

    # ── Kernel-General Operational ────────────────────────────────────────────
    ("Microsoft-Windows-Kernel-General/Operational", 12, "System time set",
     "Defense Evasion", "Log Tampering",
     "Log timeline manipulation; Kerberos ticket window abuse via time manipulation",
     "T1070.006", "High", 3),
    ("Microsoft-Windows-Kernel-General/Operational", 13, "UTC time change",
     "Defense Evasion", "Log Tampering",
     "UTC clock manipulation for timeline corruption or Kerberos ticket spoofing",
     "T1070.006", "High", 3),

    # ── Kernel-PnP Device Configuration ──────────────────────────────────────
    ("Microsoft-Windows-Kernel-PnP/Device Configuration", 400, "New device installed",
     "Initial Access,Exfiltration", "Hardware",
     "Rogue USB hardware implant; external storage for data exfil; malicious peripheral installation",
     "T1200,T1052", "High", 3),
    ("Microsoft-Windows-Kernel-PnP/Device Configuration", 410, "Device configured",
     "Initial Access", "Hardware",
     "External device configured on system; follow-on to Event 400 for hardware implant tracking",
     "T1200", "High", 3),
]

# ── Build KQL datatable ───────────────────────────────────────────────────────
def ks(s):
    """Escape a Python string as a KQL string literal."""
    return '"' + str(s).replace('"', '""') + '"'

rows = []
for ev in EVENTS:
    rows.append(
        f"  {ks(ev[0])}, {ev[1]}, {ks(ev[2])}, {ks(ev[3])}, {ks(ev[4])}, "
        f"{ks(ev[5])}, {ks(ev[6])}, {ks(ev[7])}, {ev[8]}"
    )

csl = """.set-or-replace ThreatReference <|
datatable(
    LogSource     : string,
    EventId       : int,
    EventName     : string,
    Category      : string,
    SubCategory   : string,
    ThreatActions : string,
    MitreIds      : string,
    Priority      : string,
    CollectionTier: int
)[
""" + ",\n".join(rows) + "\n]"

mgmt(csl, f"loaded {len(EVENTS)} reference records via .set-or-replace")

# ── Verify ────────────────────────────────────────────────────────────────────
body = json.dumps({"db": DB, "csl": "ThreatReference | count"}).encode()
req  = urllib.request.Request(f"{BASE}/v1/rest/query", data=body,
    headers={"Content-Type": "application/json", "Accept": "application/json"},
    method="POST")
with urllib.request.urlopen(req, timeout=30) as resp:
    d = json.loads(resp.read())
    count = d["Tables"][0]["Rows"][0][0]
    print(f"  ✓  ThreatReference verified: {count} rows")

# Priority breakdown
body = json.dumps({"db": DB,
    "csl": "ThreatReference | summarize Count=count() by Priority | order by Count desc"
}).encode()
req  = urllib.request.Request(f"{BASE}/v1/rest/query", data=body,
    headers={"Content-Type": "application/json", "Accept": "application/json"},
    method="POST")
with urllib.request.urlopen(req, timeout=30) as resp:
    d = json.loads(resp.read())
    print("")
    print("  Priority breakdown:")
    for row in d["Tables"][0]["Rows"]:
        print(f"    {row[0]:<12} {row[1]}")
PYEOF

echo ""
log "Done. Example queries:"
echo ""
echo -e "${CYAN}  // Enrich recent events with threat context${NC}"
echo '  WindowsEvents'
echo '  | where TimeCreated > ago(1h)'
echo '  | lookup kind=leftouter ThreatReference'
echo '      on $left.EventId == $right.EventId,'
echo '         $left.Channel  == $right.LogSource'
echo '  | where isnotempty(Priority)'
echo '  | project TimeCreated, Computer, EventId, EventName, Priority, Category, MitreIds'
echo '  | order by case(Priority=="Critical",0,Priority=="High",1,Priority=="Medium",2,3) asc'
echo ""
echo -e "${CYAN}  // Coverage check — which event IDs you are collecting vs the reference${NC}"
echo '  ThreatReference'
echo '  | join kind=leftouter ('
echo '      WindowsEvents | where TimeCreated > ago(24h)'
echo '      | summarize Seen=count() by EventId, Channel'
echo '    ) on $left.EventId == $right.EventId, $left.LogSource == $right.Channel'
echo '  | extend Collecting = isnotnull(Seen)'
echo '  | project Priority, LogSource, EventId, EventName, Collecting, Seen'
echo '  | order by Collecting asc, Priority asc'
echo ""
