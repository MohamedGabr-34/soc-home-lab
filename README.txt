# SOC Home Lab — Detection Engineering with Splunk

A self-built home lab for practicing detection engineering in Splunk, simulating a realistic attack chain across a multi-VM environment: **reconnaissance → initial access → persistence**. Every stage is paired with a working Splunk detection and the reasoning behind its tuning.

All three stages target the same compromised account (labtarget), simulating one continuous incident rather than three isolated exercises.

## What this lab covers

Three connected attack stages, each detected and tuned in Splunk:

1. **[Nmap port scan detection](./01-nmap-detection)** — reconnaissance (MITRE T1046)
2. **[SSH brute force detection](./02-ssh-bruteforce)** — initial access (MITRE T1110)
3. **[SSH key persistence detection](./03-ssh-persistence)** — persistence after compromise (MITRE T1098.004)

For the full picture, see the [Detection Coverage Summary](#detection-coverage-summary) below.

## Architecture

| Role | Machine | Details |
|---|---|---|
| SIEM | Windows 11 host | Splunk Enterprise |
| Victim | Debian 13 VM (`debiansrv1`) | Splunk Universal Forwarder |
| Attacker | Rocky Linux 9 VM (`rockysrv1`) | nmap, custom Python (paramiko) brute-force script |

Network: VMware Workstation, NAT (VMnet8), with the host acting as the SIEM indexer.

## Detection Coverage Summary

| Stage | Technique | Log source | Detection type |
|---|---|---|---|
| Reconnaissance | T1046 — Network Service Discovery | nftables (custom rule) | Threshold: unique ports per source |
| Initial access | T1110 — Brute Force | journald (`sshd`) | Threshold + "successful login" condition |
| Persistence | T1098.004 — SSH Authorized Keys | auditd (file watch) | Binary: single match is the alert |

## Skills Demonstrated

- Splunk Universal Forwarder deployment on Linux, forwarding to a Windows indexer
- Two distinct Linux logging mechanisms and their matching Splunk input types: `monitor` for plain text log files (`dpkg.log`, `auditd`'s `audit.log`) vs `journald` for the systemd journal (kernel messages, `sshd`)
- Custom log sources where none existed by default: an `nftables` connection-logging rule and an `auditd` file-integrity watch rule
- SPL: `rex` field extraction, `stats` with `eval()` conditions, `where` filtering
- Two different detection patterns: volume/threshold-based (nmap, brute force) vs. binary "any occurrence is the alert" (persistence)
- MITRE ATT&CK mapping for each stage
- Real-world troubleshooting: VM networking, Splunk port/auth issues, package mirror failures, log timestamp parsing bugs

## Setup

Full per-stage setup lives in each lab's own README. The shared foundation is below.

### 1. Install Splunk Enterprise (SIEM host)
Install on Windows, then enable a receiving port for forwarders:
- Settings → Forwarding and receiving → Configure receiving → New Receiving Port → `9997`
- Allow inbound TCP 9997 through the host firewall

### 2. Install the Universal Forwarder (victim)
```bash
sudo dpkg -i splunkforwarder-10.6.1.1-*.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

### 3. Point the forwarder at the SIEM
```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server <SIEM-IP>:9997
sudo /opt/splunkforwarder/bin/splunk list forward-server   # confirm it shows under Active forwards
```

### 4. Verify the pipeline (sanity check before building anything real)
`dpkg.log` was used purely to prove data actually flows end-to-end, it plays no role in any detection below. It was picked because it was the one file world-readable by the forwarder's low-privilege `splunkfwd` user at the time; everything else in `/var/log` was root-only.
```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/dpkg.log
```
Search in Splunk: `index=main host=debiansrv1 source="/var/log/dpkg.log"`

### 5. Add real data inputs
Two input types are used, matched to where each log actually lives:

| Input type | Use for | Example |
|---|---|---|
| `monitor` | A plain text file on disk | `[monitor:///var/log/audit/audit.log]` |
| `journald` | systemd's binary journal (not a readable file — Splunk runs `journalctl` behind the scenes) | `[journald://ssh-lab]` |

```bash
# monitor — direct file path
sudo /opt/splunkforwarder/bin/splunk add monitor /path/to/file

# journald — requires read access to the journal first
sudo usermod -aG systemd-journal splunkfwd
sudo mkdir -p /opt/splunkforwarder/etc/apps/journald_input/local
```
Then add a stanza to `.../journald_input/local/inputs.conf`:
```ini
[journald://ssh-lab]
journalctl-unit = ssh
journalctl-grep = Failed password|Accepted password
index = main
```
Restart as a service (not just `splunk restart`, since it runs under systemd):
```bash
sudo systemctl restart SplunkForwarder
```

## Troubleshooting Notes

**VM gets no IPv4 address after bridging over Wi-Fi**
Bridged networking can silently fail to get a DHCP lease over some Wi-Fi adapters. Switch to NAT, it uses the hypervisor's own DHCP server and doesn't depend on the host's router cooperating.

**Forwarding to the SIEM times out on the management port**
8089 is Splunk's default management port, but not guaranteed, if something else is already using it, Splunk falls back silently (8090, in this case).
 Check what's actually bound rather than assuming the default:
 ```bash
netstat -ano | findstr "8089 8090"
```
 
 
**Forwarder login suddenly fails ("Login failed" / "No users exist")**
If local admin credentials are lost, don't guess, reset cleanly with a seed file (password must be 8+ characters or Splunk silently ignores the file):
```bash
sudo bash -c 'cat > /opt/splunkforwarder/etc/system/local/user-seed.conf << EOF
[user_info]
USERNAME = admin
PASSWORD = <new password>
EOF'
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

**Event timestamps are wrong, sometimes off by hours, inconsistently**
Found via a journald-sourced input: most events had correct `_time`, but some were off by a large, inconsistent amount. Cross-checking `_time` against `_indextime` (when Splunk actually received the event) showed the gap only appeared on events containing a MAC address field ending in `:08:00`. Splunk's automatic timestamp detection was misreading that as a clock time (08:00) inside the raw text. Fix: force the sourcetype to use arrival time instead of scanning the text, in `props.conf` on the indexer:
```ini
[journald]
DATETIME_CONFIG = CURRENT
```

**Package installs failing with 404s, or downloading corrupted/wrong content**
Regional package mirrors can be stale or, in one case, actively intercepted by an ISP (HTTP requests silently redirected to an ISP landing page, even over a specific HTTPS mirror with a certificate mismatch). Fixes used:
- Switch `http://` sources to `https://` where the repo supports it
- Prefer the distro's main CDN-backed mirror (`deb.debian.org`) over a specific regional one
- As a last resort, download the exact `.deb` manually and resolve dependency versions one at a time with `dpkg -i`