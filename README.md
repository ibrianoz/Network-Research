# Network-Research
---
![Network Research](https://github.com/ibrianoz/Network-Research/blob/a878c5a034f202968a8f6ade94706e91248554f9/NX201.png)
## 📖 Executive Summary

The **Network-Research** is a comprehensive Bash-based security framework designed to automate the initial phases of network penetration testing while strictly maintaining operational security (OpSec).

Unlike standard scanners that run locally, this tool establishes a secure SSH connection to a remote server and uses it as a **pivot point** to scan targets. All control traffic is routed through the **Tor network** using **NIPE**, ensuring the auditor's true location remains obfuscated.

## ✨ Key Features

* **🛡️ Anonymity & OpSec:**
    * **NIPE Integration:** Routes traffic through Tor.
    * **Geo-Location Kill Switch:** Automatically checks the Tor exit node. If the exit IP is located in Israel (`IL`), the script forces a circuit rebuild to prevent local exposure.
* **📡 Remote Pivot Scanning:**
    * Executes `nmap`, `whois`, and `ping` commands directly on the remote server using `sshpass`.
    * Minimizes local bandwidth usage and keeps attack traffic local to the target network.
* **🔍 Hybrid Scanning Engine:**
    * **Fast Scan:** Rapid TCP SYN scan to identify open ports (`--min-rate 300`).
    * **Deep Scan:** Targeted vulnerability analysis (`--script vuln`) run *only* on the detected open ports.
* **💾 Fail-Safe Data Recovery:**
    * Features an intelligent `cleanup` trap. If the script is interrupted (Ctrl+C) or crashes, it automatically connects to the remote server to recover any partial data before wiping the remote workspace.
* **📊 Automated Reporting:**
    * Generates structured **Markdown** and **Text** reports.
    * Includes session metadata (Folder size, Time, Tor Exit IP) and parsed vulnerability findings.

---

## ⚙️ Technical Implementation

### 1. Anonymity Verification
The script ensures your IP is masked before any operation begins. It specifically validates that the Tor exit node is not local.

```bash
# Verify anonymity: Ensure exit node is NOT Israel (IL)
RESULT=$(curl -s --max-time 8 [https://wtfismyip.com/json](https://wtfismyip.com/json))
COUNTRY=$(echo "$RESULT" | jq -r '.YourFuckingCountryCode // empty')

if [[ "$COUNTRY" != "IL" ]]; then
    echo -e "${GREEN}[NIPE] Anonymity verified.${RESET}"
    return 0
else
    echo -e "${RED}[NIPE] Still IL exit. Retrying...${RESET}"
fi
2. Remote Pivot Execution
Commands are injected over SSH without requiring interactive shell access.

Bash

# Execute commands remotely without user interaction
# -o StrictHostKeyChecking=no: Prevents "yes/no" prompts
sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
    "$REMOTE_USER@$REMOTE_HOST" "command_to_run"
3. Intelligent Hybrid Scan Logic
To optimize speed, the script does not run heavy scans on all ports. It discovers, filters, and then analyzes.

Bash

# 1. FAST SCAN: High rate, limited retries
nmap -Pn -p- -T3 --max-retries 1 --min-rate 300 -oG output.gnmap $TARGET

# 2. EXTRACT PORTS: Regex parse open ports
OPEN_PORTS=$(grep -oP '\d+(?=/open)' output.gnmap | paste -sd, -)

# 3. DEEP SCAN: Targeted vulnerability analysis on SPECIFIC ports only
nmap -Pn -sV --script vuln -p $OPEN_PORTS -T3 -oA deep_scan $TARGET
4. Interrupt Safety (The Cleanup Trap)
Operational security requires leaving no trace. This function ensures remote files are deleted even if the script crashes.

Bash

# Trap signals to trigger the cleanup function
trap cleanup SIGINT
trap cleanup ERR

cleanup() {
    log "Interrupt detected — inspecting remote directory..."
    # Attempt SCP recovery of partial data before deletion
    sshpass -p "$SSH_PASS" scp -r ... "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_SAVE/"
    # Securely remove remote evidence
    sshpass ... "rm -rf $REMOTE_DIR"
}
🚀 Usage
Prerequisites
OS: Kali Linux (or Debian-based distribution).

User: Must be run as root (Sudo).

Remote Server: A VPS or remote machine with SSH access and sudo privileges.

Installation
The script acts as a self-installer. It will automatically check for and install missing dependencies (nipe, tor, sshpass, jq, etc.) upon the first run.

Download the script:

Bash

git clone [https://github.com/ibrianoz/Network-Research](https://github.com/ibrianoz/Network-Research.git)
cd Network-Research
Make executable:

Bash

chmod +x S10.NX201.sh
Run:

Bash

sudo ./S10.NX201.sh
Operation
Session Setup: Enter a name for the current audit session.

SSH Config: Provide the IP, Port, User, and Password for the remote pivot server.

Select Mode:

Option 1: Single Target Scan (IP).

Option 2: Network Scan (Auto-detects remote CIDR and scans live hosts).
