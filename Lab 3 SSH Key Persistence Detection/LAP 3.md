# Lab 3: SSH Key Persistence Detection

## Goal
Detect an attacker planting their own SSH key for persistent access (MITRE T1098.004 — Account Manipulation: SSH Authorized Keys),
 the stage after initial compromise where an attacker ensures they can return even if the original 
credentials change.

**This lab continues directly from [Lab 2](../02-ssh-bruteforce):** the attacker is assumed to already hold valid credentials for `labtarget`, 
obtained there via brute force. Rather than relying on that password for future access 
(which could be changed or locked out), the attacker now plants their own SSH key, trading a crackable credential for a permanent one.
## Setup
Unlike the previous two labs, this isn't something the journal captures, file edits aren't a service logging its own activity, 
so there's no event for it anywhere by default. File-integrity monitoring requires a dedicated tool.

**1. Install auditd** (victim machine):
```bash
sudo apt install auditd -y
```

**2. Ensure the target file exists first.** `auditd` can only watch a file that's already present:
```bash
sudo mkdir -p /home/labtarget/.ssh
sudo touch /home/labtarget/.ssh/authorized_keys
sudo chown -R labtarget:labtarget /home/labtarget/.ssh
sudo chmod 700 /home/labtarget/.ssh
sudo chmod 600 /home/labtarget/.ssh/authorized_keys
```

**3. Add a watch rule:**
```bash
sudo nano /etc/audit/rules.d/audit.rules
```
```
-w /home/labtarget/.ssh/authorized_keys -p wa -k ssh-persistence
```
```bash
sudo augenrules --load
```

**4. Splunk input.** auditd writes its own log file rather than going through the journal, so this uses `monitor`, not `journald`:
```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log
```

## The Attack
Simulates an attacker who already holds valid credentials for the target account (continuing the narrative from Lab 2) and plants their own key for passwordless, persistent access:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/attacker_key -N ""
ssh labtarget@<victim-ip> "echo \"$(cat ~/.ssh/attacker_key.pub)\" >> ~/.ssh/authorized_keys"
```
Verified by logging in with no password at all:
```bash
ssh -i ~/.ssh/attacker_key labtarget@<victim-ip>
```

## Detection
```spl
index=main host=<victim-host> source="/var/log/audit/audit.log" key="ssh-persistence"
```
No threshold needed, this is a binary detection: there is no legitimate reason for this specific file to be modified outside of deliberate admin setup, 
so a single match is itself the alert.

## Evidence
*(screenshots: the raw audit event showing the file write, process, and account; the passwordless login proving persistence actually works)*

## Tuning
- No volume threshold required, unlike Labs 1 and 2. Worth noting as a deliberate contrast: not every detection needs a "how many is too many" judgment call, 
 some actions are inherently suspicious regardless of frequency.
- Fields (`AUID`, `exe`, `key`) were auto-extracted by Splunk from auditd's native `key="value"` log format, no `rex` needed here,
  unlike the other two labs where raw kernel/syslog text required manual field extraction.

## MITRE ATT&CK
**T1098.004 — Account Manipulation: SSH Authorized Keys**

## What I Learned
- Detection coverage has to be built deliberately; a stock Linux install logs almost nothing about file changes,
 even highly sensitive ones like `authorized_keys`, until a tool like `auditd` is explicitly configured to watch for it.
- Not all detections are threshold-based, some are "did this ever happen at all," which is a meaningfully different kind of rule to write and justify.