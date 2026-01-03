#!/bin/bash
#student:
	#Name: Oz Itzkowitz
	#Number: S10
	#Class: TMagen7736/37
	#Teacher: Erel Regev

########################################################
# GLOBAL SETTINGS
########################################################

HOME=/home/kali/Desktop
TOOL="$HOME/nipe_tool"

#COLOR
YELLOW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

#BOLD
BOLD_YELLOW='\033[1;33m'
BOLD_RED='\033[1;31m'
BOLD_GREEN='\033[1;32m'
BOLD='\033[1m'

SCRIPT_START=$(date +%s)

# Detect the non-root user who launched the script - not working fully
REAL_USER="${SUDO_USER:-$USER}"
REAL_UID=$(id -u "$REAL_USER")
REAL_GID=$(id -g "$REAL_USER")


 ########################################################
 # CHECK ROOT
 ########################################################
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root.${RESET}"
        exit 1
    else
        echo -e "${GREEN}${BOLD}You are root. Starting script...\n${RESET}"
    fi
    
mkdir -p "$TOOL"


########################################################
# LOGGING
########################################################
log() {
    mkdir -p "$(dirname "$LOG_FILE")"

    local ts msg
    ts="$(date "+[%Y-%m-%d %H:%M:%S]")"
    msg="$1"

    # Always write to log file
    printf "%s %s\n" "$ts" "$msg" >> "$LOG_FILE"

    # Silence terminal output
    return 0
}

########################################################
# CLEANUP — NO PROMPTS 
########################################################
cleanup() {
    echo -e "${YELLOW}[!] Cleanup triggered...${RESET}"
    log "Cleanup triggered (audit start)."

    #
    # 1. Stop NIPE if it's running
    #
    if [ -f "$TOOL/nipe/nipe.pl" ]; then
        log "NIPE detected — attempting to stop NIPE."
        sudo perl "$TOOL/nipe/nipe.pl" stop >/dev/null 2>&1
        EXIT_NIPE=$?
        if [[ $EXIT_NIPE -eq 0 ]]; then
            log "NIPE stop command executed successfully."
        else
            log "WARNING: NIPE stop command failed with exit code $EXIT_NIPE."
        fi
    else
        log "NIPE not present — skipping NIPE shutdown."
    fi


    #
    # 2. If remote scan temp folder exists, attempt recovery
    #
    if [[ -n "$REMOTE_DIR" ]]; then
        log "Interrupt detected — inspecting remote directory: $REMOTE_DIR"

        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" "[ -d \"$REMOTE_DIR\" ]"
        SSH_CHECK=$?

        if [[ $SSH_CHECK -eq 0 ]]; then
            log "Remote directory exists — starting audit of remote contents."

            FILE_COUNT=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
                "$REMOTE_USER@$REMOTE_HOST" "find \"$REMOTE_DIR\" -type f | wc -l")
            EXIT_FC=$?

            if [[ $EXIT_FC -eq 0 ]]; then
                log "Remote file count retrieved: $FILE_COUNT files."
            else
                log "ERROR: Failed to retrieve file count from remote directory (exit $EXIT_FC)."
            fi

            if [[ "$FILE_COUNT" -gt 0 ]]; then
                log "Files exist — initiating remote recovery process."

                LOCAL_SAVE="$EXTRACT_DIR/recovered_interrupt"
                log "Creating local recovery folder: $LOCAL_SAVE"
                mkdir -p "$LOCAL_SAVE"

                log "Applying remote chmod to ensure readability."
                sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
                    "$REMOTE_USER@$REMOTE_HOST" "echo \"$SSH_PASS\" | sudo -S chmod -R 755 \"$REMOTE_DIR\"" >/dev/null 2>&1
                EXIT_CHMOD=$?
                log "Remote chmod exit code: $EXIT_CHMOD"

                log "Beginning SCP recovery from remote."
                sshpass -p "$SSH_PASS" scp -r -o StrictHostKeyChecking=no -P "$REMOTE_PORT" \
                    "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_SAVE/" >/dev/null 2>&1
                EXIT_SCP=$?

                if [[ $EXIT_SCP -eq 0 ]]; then
                    log "SCP recovery successful — files saved to: $LOCAL_SAVE"
                else
                    log "ERROR: SCP recovery failed (exit code $EXIT_SCP)."
                fi

                log "Removing remote directory."
                sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
                    "$REMOTE_USER@$REMOTE_HOST" "echo \"$SSH_PASS\" | sudo -S rm -rf \"$REMOTE_DIR\"" >/dev/null 2>&1
                EXIT_RM=$?

                if [[ $EXIT_RM -eq 0 ]]; then
                    log "Remote directory removed successfully."
                else
                    log "ERROR: Failed to delete remote directory (exit code $EXIT_RM)."
                fi

            else
                log "Remote directory contains zero files — removing directory."

                sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
                    "$REMOTE_USER@$REMOTE_HOST" "echo \"$SSH_PASS\" | sudo -S rm -rf \"$REMOTE_DIR\"" >/dev/null 2>&1
                EXIT_EMPTY_RM=$?

                if [[ $EXIT_EMPTY_RM -eq 0 ]]; then
                    log "Remote empty directory removed."
                else
                    log "ERROR: Failed to remove empty remote directory (exit $EXIT_EMPTY_RM)."
                fi
            fi

        else
            log "Remote directory does NOT exist or SSH failed (exit $SSH_CHECK)."
        fi
    else
        log "No remote directory variable defined — skipping remote cleanup."
    fi


    #
    # 3. Remove incomplete local session folder only if empty
    #
    if [[ -n "$SESSION_DIR" && -d "$SESSION_DIR" ]]; then
        log "Checking local session directory for meaningful data: $SESSION_DIR"

        NON_EMPTY_COUNT=$(find "$SESSION_DIR" \
            -path "$SESSION_DIR/raw_archives" -prune -o \
            -type f -size +0c -print | wc -l)
        EXIT_NEC=$?

        if [[ $EXIT_NEC -eq 0 ]]; then
            log "Local non-empty file count: $NON_EMPTY_COUNT"
        else
            log "ERROR: Failed to evaluate local session folder (exit $EXIT_NEC)."
        fi

        if [[ "$NON_EMPTY_COUNT" -eq 0 ]]; then
            log "Local session directory empty — removing: $SESSION_DIR"
            rm -rf "$SESSION_DIR"
            EXIT_LOCAL_RM=$?
            log "Local delete exit code: $EXIT_LOCAL_RM"
        else
            log "Local session directory contains data — not deleting."
        fi
    else
        log "Local session directory variable missing or not a directory."
    fi


    #
    # 4. Wrap up
    #
    RUNTIME=$(( $(date +%s) - SCRIPT_START ))
    log "Cleanup runtime: $RUNTIME seconds"
    log "Cleanup procedure completed (audit end)."

    exit 1
}

trap cleanup SIGINT
trap cleanup ERR

########################################################
# CHECK LOCAL DEPENDENCIES 
########################################################
CHECK_APPS() {

    log "CHECK_APPS() invoked — verifying local system dependencies."

    apps=( "curl" "jq" "git" "sshpass" "nmap" "tar" "whois" )

    OK="\u2714"      # ✔
    FAIL="\u2718"    # ✘

    echo -e "${GREEN}[Checking local dependencies]${RESET}"
    log "Beginning dependency validation for ${#apps[@]} applications."

    for a in "${apps[@]}"; do

        log "Checking local presence of dependency: $a"

        if command -v "$a" >/dev/null 2>&1; then
            echo -e "${GREEN}[${OK}] $a is already installed${RESET}"
            log "Dependency OK: $a is installed."

        else
            echo -e "${YELLOW}[${FAIL}] $a not found — installing...${RESET}"
            log "Dependency missing: $a — attempting installation via apt-get."

            apt-get install -y "$a" >/dev/null 2>&1
            EXIT_APT=$?

            log "apt-get install exit code for $a: $EXIT_APT"

            if command -v "$a" >/dev/null 2>&1; then
                echo -e "${GREEN}[${OK}] $a installed successfully${RESET}"
                log "Installation successful: $a"
            else
                echo -e "${RED}[${FAIL}] Failed to install $a${RESET}"
                log "ERROR: Installation failed for dependency: $a"
            fi
        fi

    done

    log "CHECK_APPS() completed."
}

########################################################
# SSH_REMOTE_INFO
########################################################
SSH_REMOTE_INFO() {

    log "SSH_REMOTE_INFO() invoked — starting remote SSH setup prompts."
    echo -e "${GREEN}[SSH SETUP]${RESET}"

	#set attempts 
    local attempts=0
    local max_attempts=3
    log "Maximum SSH connection attempts: $max_attempts"

    while (( attempts < max_attempts )); do
        attempts=$((attempts + 1))

        echo -e "${YELLOW}Attempt $attempts of $max_attempts${RESET}"
        log "Attempt $attempts/$max_attempts: collecting SSH credentials."

        ############################################################
        # USERNAME
        ############################################################
        read -rp "Remote SSH username: " REMOTE_USER
        if [[ -z "$REMOTE_USER" ]]; then
            echo -e "${RED}Username cannot be empty.${RESET}"
            log "Invalid SSH username: empty"
            continue
        fi
        log "User entered SSH username: $REMOTE_USER"

        ############################################################
        # REMOTE HOST + IPv4 VALIDATION
        ############################################################
        read -rp "Remote IP/hostname: " REMOTE_HOST
        if [[ -z "$REMOTE_HOST" ]]; then
            echo -e "${RED}Host/IP cannot be empty.${RESET}"
            log "Invalid SSH host: empty"
            continue
        fi

        # IP structure check
        if ! [[ "$REMOTE_HOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo -e "${RED}Invalid IP format. Use A.B.C.D${RESET}"
            log "Invalid IP format provided: $REMOTE_HOST"
            continue
        fi

        # IP octet range check
        IFS='.' read -r O1 O2 O3 O4 <<< "$REMOTE_HOST"
        for o in "$O1" "$O2" "$O3" "$O4"; do
            if (( o < 0 || o > 255 )); then
                echo -e "${RED}IP octets must be in range 0–255.${RESET}"
                log "Invalid IP (out of range): $REMOTE_HOST"
                continue 2
            fi
        done

        log "User entered valid SSH host/IP: $REMOTE_HOST"

        ############################################################
        # PORT (default 22)
        ############################################################
        read -rp "Remote port [22]: " REMOTE_PORT
        REMOTE_PORT="${REMOTE_PORT:-22}"
        log "User entered SSH port: $REMOTE_PORT"

        ############################################################
        # PASSWORD
        ############################################################
        read -rsp "Password (for SSH login): " SSH_PASS
        echo ""
        if [[ -z "$SSH_PASS" ]]; then
            echo -e "${RED}Password cannot be empty.${RESET}"
            log "Empty SSH password entered"
            continue
        fi
        log "SSH password entered (value not logged)."

        ############################################################
        # SSH CONNECTION TEST
        ############################################################
        echo -e "${YELLOW}[*] Testing SSH connection to $REMOTE_USER@$REMOTE_HOST:${REMOTE_PORT}...${RESET}"
        log "Testing SSH connectivity to $REMOTE_USER@$REMOTE_HOST:$REMOTE_PORT"

        sshpass -p "$SSH_PASS" \
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" "echo connected" >/dev/null 2>&1

        EXIT_SSH=$?
        log "SSH test exit code: $EXIT_SSH"

        if [[ $EXIT_SSH -eq 0 ]]; then
            echo -e "${GREEN}[✔] SSH connection successful!${RESET}"
            log "SSH connection successful — proceeding to REMOTE_SYSTEM_INFO()."

            REMOTE_SYSTEM_INFO
            log "REMOTE_SYSTEM_INFO() completed."

            return 0
        else
            echo -e "${RED}[✘] SSH connection failed!${RESET}"
            log "SSH connection failed on attempt $attempts."
            echo ""
        fi

    done

    ############################################################
    # FAILURE AFTER ALL ATTEMPTS
    ############################################################
    echo -e "${RED}[!] Maximum attempts reached. Connection failed.${RESET}"
    log "ERROR: All SSH connection attempts failed. Exiting."
    exit 1
}


########################################################
# REMOTE TOOLS - nmap, tar, whois
########################################################
REMOTE_CHECK_TOOLS() {

    log "REMOTE_CHECK_TOOLS() invoked — validating remote required tools."
    echo -e "${YELLOW}[REMOTE] Ensuring required tools are installed...${RESET}"

    log "Attempting remote installation check for: nmap, tar, whois"

    sshpass -p "$SSH_PASS" \
        ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S apt-get install -y nmap tar whois >/dev/null 2>&1"

    EXIT_REMOTE_INSTALL=$?
    log "Remote apt-get install exit code: $EXIT_REMOTE_INSTALL"

    if [[ $EXIT_REMOTE_INSTALL -eq 0 ]]; then
        log "Remote tools verified successfully (nmap, tar, whois)."
        echo -e "${GREEN}[REMOTE] Tools verified (nmap, tar, whois installed).${RESET}"
    else
        log "ERROR: Remote tool installation failed. Exit code: $EXIT_REMOTE_INSTALL"
        echo -e "${RED}[REMOTE] Failed to verify remote tools!${RESET}"
    fi
}
########################################################
# REMOTE_SYSTEM_INFO 
########################################################
REMOTE_SYSTEM_INFO() {

    log "REMOTE_SYSTEM_INFO() invoked — gathering remote system information."

    echo -e "${GREEN}[REMOTE] Gathering remote system information...${RESET}"


    ########################################################
    # 1 — GET REMOTE PUBLIC IP (from remote server)
    ########################################################
    log "Requesting remote public IP via remote curl."

    REMOTE_PUBLIC_IP=$(sshpass -p "$SSH_PASS" \
        ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" "curl -s https://wtfismyip.com/text")
    EXIT_IP=$?

    log "Remote public IP command exit code: $EXIT_IP"
    log "Remote public IP result: ${REMOTE_PUBLIC_IP:-none}"

    if [[ -z "$REMOTE_PUBLIC_IP" ]]; then
        echo -e "${RED}[REMOTE] Could not determine remote public IP.${RESET}"
        log "ERROR: Remote public IP is empty — aborting REMOTE_SYSTEM_INFO()."
        return
    fi


    ########################################################
    # 2 — GET COUNTRY (local curl + jq)
    ########################################################
    log "Requesting local GEO JSON for country lookup."

    GEO_JSON=$(curl -s https://wtfismyip.com/json)
    EXIT_GEO=$?
    log "Local GEO JSON curl exit code: $EXIT_GEO"

    REMOTE_COUNTRY=$(echo "$GEO_JSON" | jq -r '.YourFuckingCountry // "Unknown"')
    log "Country extracted from GEO JSON: $REMOTE_COUNTRY"


    ########################################################
    # 3 — GET REMOTE UPTIME
    ########################################################
    log "Requesting remote uptime via SSH."

    REMOTE_UPTIME=$(sshpass -p "$SSH_PASS" \
        ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" "uptime -p")
    EXIT_UP=$?

    log "Remote uptime command exit code: $EXIT_UP"
    log "Remote uptime result: ${REMOTE_UPTIME:-none}"


    ########################################################
    # OUTPUT (screen only)
    ########################################################
    log "Displaying remote system info summary."

    echo ""
    echo -e "${GREEN}====== REMOTE SERVER INFO ======${RESET}"
    echo -e "${BOLD}Public IP:   ${RESET}$REMOTE_PUBLIC_IP"
    echo -e "${BOLD}Country:     ${RESET}$REMOTE_COUNTRY"
    echo -e "${BOLD}Uptime:      ${RESET}$REMOTE_UPTIME"
    echo -e "${GREEN}================================${RESET}"
    echo ""

    log "REMOTE_SYSTEM_INFO() completed successfully."
}

########################################################
# CHECK_TOR
########################################################
CHECK_TOR() {

    log "CHECK_TOR() invoked — verifying Tor service status."
    echo -e "${GREEN}[TOR] Checking Tor service...${RESET}"

    #
    # Systemd check
    #
    log "Checking if systemctl exists on this system."
    if command -v systemctl >/dev/null 2>&1; then

        log "systemctl found — checking Tor service state."

        # Check if Tor is active
        if systemctl is-active --quiet tor; then
            echo -e "${GREEN}[✔] Tor is already running.${RESET}"
            log "Tor is already running (systemd active)."
            return 0
        else
            echo -e "${YELLOW}[TOR] Tor not running — starting it...${RESET}"
            log "Tor is not active — attempting to start via systemctl."

            systemctl enable tor >/dev/null 2>&1
            EXIT_ENABLE=$?
            log "systemctl enable tor exit code: $EXIT_ENABLE"

            systemctl start tor >/dev/null 2>&1
            EXIT_START=$?
            log "systemctl start tor exit code: $EXIT_START"

            if systemctl is-active --quiet tor; then
                echo -e "${GREEN}[✔] Tor started successfully.${RESET}"
                log "Tor started successfully (systemctl active)."
                return 0
            else
                echo -e "${RED}[✘] Failed to start Tor.${RESET}"
                log "ERROR: Tor failed to start — systemctl reports inactive."
                return 1
            fi
        fi

    else
        #
        # No systemd — fallback check
        #
        log "systemctl NOT available — using fallback pidof check."

        if pidof tor >/dev/null 2>&1; then
            echo -e "${GREEN}[✔] Tor process detected.${RESET}"
            log "Tor running (detected via pidof)."
            return 0
        else
            echo -e "${RED}[✘] Tor is not running and systemctl unavailable.${RESET}"
            log "ERROR: Tor not running — no systemctl and no Tor pid found."
            return 1
        fi

    fi
}
########################################################
# NIPE 
########################################################
NIPE() {

    log "NIPE() invoked — starting NIPE/Tor anonymization routine."

    CHECK_TOR
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[NIPE] Tor not ready. Aborting.${RESET}"
        log "CHECK_TOR() failed — NIPE aborted."
        return 1
    fi
    log "CHECK_TOR() successful — Tor ready."


    ########################################################
    # Ensure NIPE is installed
    ########################################################
    if [ ! -f "$TOOL/nipe/nipe.pl" ]; then
        log "NIPE not installed — calling NIPE_INSTALL()."
        NIPE_INSTALL
        if [[ $? -ne 0 ]]; then
            log "ERROR: NIPE_INSTALL() failed."
            return 1
        fi
        log "NIPE installed successfully."
    else
        log "NIPE installation found at $TOOL/nipe/nipe.pl"
    fi


    ########################################################
    # cd into NIPE directory
    ########################################################
    cd "$TOOL/nipe"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[NIPE] Failed to enter nipe directory.${RESET}"
        log "ERROR: cd to $TOOL/nipe failed."
        return 1
    fi
    log "Changed directory to $TOOL/nipe"


    ########################################################
    # Restart NIPE and verify anonymity
    ########################################################
    MAX_RETRIES=5
    ATTEMPT=1
    log "Starting NIPE restart loop — max retries: $MAX_RETRIES"

    while (( ATTEMPT <= MAX_RETRIES )); do

        log "NIPE restart attempt $ATTEMPT of $MAX_RETRIES"
        echo -e "${YELLOW}[NIPE] Restarting anonymization (Attempt $ATTEMPT/$MAX_RETRIES)...${RESET}"

        perl nipe.pl restart >/dev/null 2>&1
        EXIT_RESTART=$?
        log "perl nipe.pl restart exit code: $EXIT_RESTART"

        sleep 3

        ####################################################
        # Check exit node IP from API
        ####################################################
        log "Fetching exit IP from wtfismyip.com/json"
        RESULT=$(curl -s --max-time 8 https://wtfismyip.com/json)
        CURL_EXIT=$?
        log "curl exit code: $CURL_EXIT"

        EXIT_IP=$(echo "$RESULT" | jq -r '.YourFuckingIPAddress // empty')
        COUNTRY=$(echo "$RESULT" | jq -r '.YourFuckingCountryCode // empty')

        log "API result — IP: ${EXIT_IP:-none}, Country: ${COUNTRY:-none}"

        # Validate response
        if [[ -z "$EXIT_IP" || -z "$COUNTRY" ]]; then
            echo -e "${RED}[NIPE] Invalid API response. Retrying...${RESET}"
            log "Invalid API response (missing IP or COUNTRY). Retrying."
            ((ATTEMPT++))
            continue
        fi


        ####################################################
        # Check anonymity
        ####################################################
        if [[ "$COUNTRY" != "IL" ]]; then
            echo -e "${GREEN}[NIPE] Anonymity verified.${RESET}"
            echo -e "${GREEN}Exit IP: $EXIT_IP ($COUNTRY)${RESET}"

            log "Anonymity achieved — Exit IP: $EXIT_IP Country: $COUNTRY"
            return 0
        fi

        log "NIPE still returning IL exit ($EXIT_IP). Retrying."
        echo -e "${RED}[NIPE] Still IL exit ($EXIT_IP). Retrying...${RESET}"

        ((ATTEMPT++))
        sleep 3
    done


    ########################################################
    # Failure after retries
    ########################################################
    echo -e "${RED}[NIPE] Failed to anonymize after $MAX_RETRIES attempts.${RESET}"
    log "ERROR: Failed to anonymize after $MAX_RETRIES attempts."
    return 1
}

########################################################
# NIPE_INSTALL 
########################################################
NIPE_INSTALL() {

    log "NIPE_INSTALL() invoked — starting NIPE installation routine."
    echo -e "${YELLOW}[NIPE] Installing NIPE...${RESET}"

    mkdir -p "$TOOL"
    log "Ensured TOOL directory exists: $TOOL"

    cd "$TOOL"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[NIPE] Cannot cd into $TOOL${RESET}"
        log "ERROR: Failed to cd into $TOOL"
        return 1
    fi
    log "Changed directory to $TOOL"


    ########################################################
    # Clone NIPE if missing
    ########################################################
    if [ ! -d "nipe" ]; then
        log "NIPE directory missing — attempting git clone."
        git clone https://github.com/htrgouvea/nipe nipe >/dev/null 2>&1
        GIT_EXIT=$?
        log "git clone exit code: $GIT_EXIT"

        if [[ $GIT_EXIT -ne 0 ]]; then
            echo -e "${RED}[NIPE] Git clone failed.${RESET}"
            log "ERROR: git clone failed — NIPE installation aborted."
            return 1
        fi

        log "NIPE repository cloned successfully."
    else
        echo -e "${YELLOW}[NIPE] Folder exists, skipping clone.${RESET}"
        log "NIPE directory already exists — skipping git clone."
    fi


    ########################################################
    # Enter NIPE directory
    ########################################################
    cd nipe
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[NIPE] Failed to enter nipe directory.${RESET}"
        log "ERROR: Cannot cd into nipe directory."
        return 1
    fi
    log "Entered nipe directory."


    ########################################################
    # Install Perl dependencies
    ########################################################
    echo -e "${YELLOW}[NIPE] Installing Perl dependencies...${RESET}"
    log "Installing Perl dependencies using cpanm."
    cpanm --notest --quiet --installdeps . >/dev/null 2>&1
    CPAN_EXIT=$?
    log "cpanm dependency install exit code: $CPAN_EXIT"


    ########################################################
    # Run NIPE installer
    ########################################################
    echo -e "${YELLOW}[NIPE] Running installer...${RESET}"
    log "Running: perl nipe.pl install -y"
    perl nipe.pl install -y >/dev/null 2>&1
    INSTALL_EXIT=$?
    log "perl nipe.pl install exit code: $INSTALL_EXIT"


    ########################################################
    # Validate installation
    ########################################################
    if [ ! -f nipe.pl ]; then
        echo -e "${RED}[NIPE] Installation failed. nipe.pl missing.${RESET}"
        log "ERROR: NIPE installation validation failed — nipe.pl missing."
        return 1
    fi


    ########################################################
    # Success
    ########################################################
    echo -e "${GREEN}[NIPE] Installation completed successfully.${RESET}"
    log "NIPE installation completed successfully — nipe.pl found."

    return 0
}
########################################################
# START SESSION  (FULL AUDIT LOGGING)
########################################################
START() {

    #
    # GET SESSION NAME FIRST
    #
    read -rp "Enter session name: " USER_SESSION
    [[ -z "$USER_SESSION" ]] && USER_SESSION="scan"
    echo "[INFO] Session name: $USER_SESSION"

    #
    # BUILD SESSION PATHS
    #
    SESSION_NAME="${USER_SESSION}_$(date +"%d.%m.%Y_%H-%M")"
    SESSION_DIR="$TOOL/Sessions/$SESSION_NAME"
    SCAN_DIR="$SESSION_DIR/raw_archives"
    EXTRACT_DIR="$SESSION_DIR/extracted"
    LOG_FILE="$SESSION_DIR/session.log"

    #
    # CREATE DIRECTORIES + LOG FILE BEFORE ANY log() CALLS
    #
    mkdir -p "$SCAN_DIR" "$EXTRACT_DIR"
    touch "$LOG_FILE"

    log "START() invoked — beginning session initialization."
    log "User provided session name: $USER_SESSION"
    log "Generated session name: $SESSION_NAME"

    log "Session directories prepared:"
    log "  SESSION_DIR  = $SESSION_DIR"
    log "  SCAN_DIR     = $SCAN_DIR"
    log "  EXTRACT_DIR  = $EXTRACT_DIR"
    log "  LOG_FILE     = $LOG_FILE"

    #
    # CHECK LOCAL DEPENDENCIES
    #
    CHECK_APPS
    log "CHECK_APPS() execution finished."

    #
    # NIPE start check
    #
    log "Attempting NIPE initialization..."
    NIPE
    EXIT_NIPE=$?

    if [[ $EXIT_NIPE -eq 0 ]]; then
        log "NIPE started successfully."
    else
        log "ERROR: NIPE failed to start (exit $EXIT_NIPE). Terminating session."
        exit 1
    fi

    #
    # Remote system info collection
    #
    log "Collecting SSH remote info..."
    SSH_REMOTE_INFO
    log "SSH_REMOTE_INFO completed."

    #
    # Remote tool validation
    #
    log "Checking remote required tools..."
    REMOTE_CHECK_TOOLS
    log "REMOTE_CHECK_TOOLS completed."

    #
    # MENU
    #
    log "Launching MAIN_MENU interface..."
    MAIN_MENU
    log "MAIN_MENU exited — returning to START() workflow."

    #
    # Report generation
    #
    log "Generating session report..."
    GENERATE_REPORT
    log "Report generation completed."

    #
    # Final archive creation
    #
    FINAL_ARCHIVE="$TOOL/Sessions/${SESSION_NAME}.tar.gz"
    log "Creating final archive: $FINAL_ARCHIVE"

    tar -czf "$FINAL_ARCHIVE" -C "$TOOL/Sessions" "$SESSION_NAME"
    EXIT_TAR=$?

    if [[ $EXIT_TAR -eq 0 ]]; then
        log "Final archive successfully created."
    else
        log "ERROR: Failed to create final archive (exit $EXIT_TAR)."
    fi

    log "Fixing ownership for final archive."
    chown "$REAL_UID:$REAL_GID" "$FINAL_ARCHIVE"
    EXIT_CHOWN=$?

    if [[ $EXIT_CHOWN -eq 0 ]]; then
        log "Ownership successfully updated for archive."
    else
        log "WARNING: chown failed on archive (exit $EXIT_CHOWN)."
    fi

    log "START() completed — session fully initialized and archived."
}

##########################################
# SCAN SINGLE IP 
##########################################
REMOTE_SCAN_IP() {

    log "REMOTE_SCAN_IP() invoked."

    read -rp "Target IP: " TARGET

    # --- INPUT VALIDATION BLOCK  ---
    if [[ -z "$TARGET" ]]; then
        echo "${RED}Error: No IP given.${RESET}"
        log "Invalid input: No IP provided."
        return
    fi

    if ! [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${RED}Error: Invalid IP format. Expected A.B.C.D${RESET}"
        log "Invalid input: Bad IP format ($TARGET)"
        return
    fi

    IFS='.' read -r O1 O2 O3 O4 <<< "$TARGET"
    for o in "$O1" "$O2" "$O3" "$O4"; do
        if (( o < 0 || o > 255 )); then
            echo "${RED}Error: IP octets must be 0–255.${RESET}"
            log "Invalid input: Out-of-range octet in ($TARGET)"
            return
        fi
    done

    log "Valid IP provided: $TARGET"
    # --- END VALIDATION ---

    TS=$(date +"%Y%m%d_%H%M%S")
    REMOTE_DIR="/tmp/single_$TARGET_$TS"
    LOCAL_DIR="$EXTRACT_DIR/single_scan"

    log "Generated timestamp: $TS"
    log "Remote directory: $REMOTE_DIR"
    log "Local destination: $LOCAL_DIR"

    mkdir -p "$LOCAL_DIR"
    EXIT_MK=$?
    log "LOCAL_DIR mkdir exit code: $EXIT_MK"

    ########################################################
    # 1. Create remote directory
    ########################################################
    log "Creating remote directory: $REMOTE_DIR"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S mkdir -p $REMOTE_DIR 2>/dev/null"
    EXIT_RMK=$?
    log "Remote mkdir exit code: $EXIT_RMK"


    ########################################################
    # 2. FAST PORT DISCOVERY
    ########################################################
    log "Executing fast port scan on $TARGET"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S nmap -Pn -p- -T3 \
            --max-retries 1 --min-rate 300 --host-timeout 45s \
            -oG $REMOTE_DIR/fast_$TARGET.gnmap $TARGET 2>/dev/null"
    EXIT_FAST=$?
    log "Fast scan exit code: $EXIT_FAST"


    ########################################################
    # 3. Extract open ports
    ########################################################
    log "Extracting open ports from fast scan results."
    OPEN_PORTS=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "grep -oP '\\d+(?=/open)' $REMOTE_DIR/fast_$TARGET.gnmap | paste -sd, - 2>/dev/null")
    EXIT_PARSE=$?
    log "Port extraction exit code: $EXIT_PARSE"
    log "Extracted open ports: ${OPEN_PORTS:-none}"


    if [[ -z "$OPEN_PORTS" ]]; then
        log "No open ports found — skipping deep scan."

        log "Applying remote chmod for file retrieval."
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "echo \"$SSH_PASS\" | sudo -S chmod -R 755 $REMOTE_DIR 2>/dev/null"
        log "Remote chmod exit code: $?"

        log "Attempting to recover fast scan data via SCP."
        sshpass -p "$SSH_PASS" scp -r -o StrictHostKeyChecking=no -P "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_DIR/" >/dev/null 2>&1
        log "SCP exit code: $?"

        log "Fixing local ownership."
        chown -R "$REAL_UID:$REAL_GID" "$LOCAL_DIR"
        log "Local chown exit code: $?"

        log "Removing remote directory."
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "echo \"$SSH_PASS\" | sudo -S rm -rf $REMOTE_DIR 2>/dev/null"
        log "Remote rm exit code: $?"

        return
    fi

    log "Open ports found: $OPEN_PORTS"


    ########################################################
    # 4. DEEP SCAN
    ########################################################
    log "Starting deep scan on $TARGET (ports: $OPEN_PORTS)"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "bash -c 'echo \"$SSH_PASS\" | sudo -S nmap -Pn -sV --script vuln \
            -p $OPEN_PORTS -T3 -oA $REMOTE_DIR/deep_$TARGET $TARGET 2>/dev/null'"
    log "Deep scan exit code: $?"


	########################################################
	# 4.5 WHOIS
	########################################################
	log "Running WHOIS lookup for $TARGET"

	sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
		"$REMOTE_USER@$REMOTE_HOST" \
		"echo \"$SSH_PASS\" | sudo -S bash -c 'whois $TARGET > \"$REMOTE_DIR/whois_$TARGET.txt\"' >/dev/null 2>&1"

	log "WHOIS exit code: $?"



    ########################################################
    # 5. chmod
    ########################################################
    log "Applying remote chmod for SCP access."
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S chmod -R 755 $REMOTE_DIR 2>/dev/null"
    log "chmod exit code: $?"


    ########################################################
    # 6. SCP Download
    ########################################################
    log "Downloading scan results via SCP."
    sshpass -p "$SSH_PASS" scp -r -o StrictHostKeyChecking=no -P "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_DIR/" >/dev/null 2>&1
    log "SCP exit code: $?"


    ########################################################
    # 7. Remote Cleanup
    ########################################################
    log "Removing remote scan directory: $REMOTE_DIR"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S rm -rf $REMOTE_DIR 2>/dev/null"
    log "Remote rm exit code: $?"


    log "Single IP scan completed and saved to: $LOCAL_DIR"
}
########################################################
# REMOTE SCAN NETWORK 
########################################################
REMOTE_SCAN_NETWORK() {

    log "REMOTE_SCAN_NETWORK() invoked — starting remote network discovery."

    #
    # Detect remote interface
    #
    log "Attempting to detect default network interface on remote host."
    iface=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" "ip route | awk '/default/ {print \$5}' | head -n1")
    EXIT_IFACE=$?

    log "Primary interface detection exit code: $EXIT_IFACE"
    log "Primary detected interface: ${iface:-none}"

    if [[ -z "$iface" ]]; then
        log "Primary interface empty — trying fallback interface detection."

        iface=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" "ip -o link show | awk -F': ' '\$2!=\"lo\" {print \$2; exit}'")
        EXIT_IFACE_FALL=$?

        log "Fallback interface detection exit code: $EXIT_IFACE_FALL"
        log "Fallback detected interface: ${iface:-none}"
    fi

    if [[ -z "$iface" ]]; then
        log "ERROR: Could not detect any remote interface. Aborting."
        return 1
    fi

    log "Using remote interface: $iface"


    #
    # Detect CIDR
    #
    log "Attempting to detect CIDR for interface: $iface"

    cidr=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" "ip -o -f inet addr show $iface | awk '{print \$4}'")
    EXIT_CIDR=$?

    log "CIDR primary lookup exit code: $EXIT_CIDR"
    log "CIDR primary lookup value: ${cidr:-none}"

    if [[ -z "$cidr" ]]; then
        log "Primary CIDR empty — performing fallback CIDR lookup."

        cidr=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" "ip addr show $iface | grep 'inet ' | awk '{print \$2}'")
        EXIT_CIDR_FALL=$?

        log "CIDR fallback exit code: $EXIT_CIDR_FALL"
        log "CIDR fallback value: ${cidr:-none}"
    fi

    if [[ -z "$cidr" ]]; then
        log "ERROR: Unable to determine network CIDR. Aborting."
        return 1
    fi

    log "Using CIDR: $cidr"


    #
    # Setup session dirs
    #
    TS=$(date +"%Y%m%d_%H%M%S")
    REMOTE_DIR="/tmp/netscan_$TS"
    LOCAL_DIR="$EXTRACT_DIR/network_scan"

    log "Timestamp for scan: $TS"
    log "Remote workspace: $REMOTE_DIR"
    log "Local workspace: $LOCAL_DIR"

    mkdir -p "$LOCAL_DIR"
    log "Local mkdir exit code: $?"


    ##################################################################
    # 1. Create remote workspace
    ##################################################################
    log "Creating remote directory for network scan."

    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S mkdir -p $REMOTE_DIR 2>/dev/null"
    log "Remote mkdir exit code: $?"


    ##################################################################
    # 2. Ping sweep
    ##################################################################
    log "Starting remote ping sweep: nmap -sn -n $cidr"

    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S nmap -sn -n $cidr -oG $REMOTE_DIR/ping.gnmap 2>/dev/null"
    log "Ping sweep exit code: $?"


    ##################################################################
    # 3. Generate hosts.txt
    ##################################################################
    log "Extracting live hosts to hosts.txt."

    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S bash -c 'awk \"/Up/ {print \\\$2}\" $REMOTE_DIR/ping.gnmap > $REMOTE_DIR/hosts.txt' 2>/dev/null"
    log "hosts.txt generation exit code: $?"


    ##################################################################
    # 4. Read hosts
    ##################################################################
    log "Fetching host list for scanning."

    HOSTS=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" "cat $REMOTE_DIR/hosts.txt 2>/dev/null")
    log "Hosts detected: ${HOSTS:-none}"


    ##################################################################
    # 5. Scan each discovered host
    ##################################################################
    for h in $HOSTS; do
        log "Scanning host: $h"

        #
        # FAST SCAN
        #
        log "Running fast port scan on $h."

        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "echo \"$SSH_PASS\" | sudo -S nmap -Pn -p- -T3 \
                --max-retries 1 --min-rate 300 --host-timeout 45s \
                -oG $REMOTE_DIR/fast_$h.gnmap $h 2>/dev/null"
        log "Fast scan exit code: $?"

        #
        # Extract ports
        #
        OPEN_PORTS=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "grep -oP '\\d+(?=/open)' $REMOTE_DIR/fast_$h.gnmap | paste -sd, -")
        log "Open port extraction exit code: $?"
        log "Open ports for $h: ${OPEN_PORTS:-none}"

        [[ -z "$OPEN_PORTS" ]] && { log "No open ports on $h — skipping deep scan."; continue; }


        #
        # DEEP SCAN
        #
        log "Running deep scan on $h (ports: $OPEN_PORTS)."

        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "echo \"$SSH_PASS\" | sudo -S bash -c 'nmap -Pn -sV --script vuln \
                -p \"$OPEN_PORTS\" -T3 -oA $REMOTE_DIR/deep_$h $h' 2>/dev/null"
        log "Deep scan exit code: $?"


        #
        # WHOIS
        #
        log "Collecting WHOIS info for: $h"

        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
            "$REMOTE_USER@$REMOTE_HOST" \
            "echo \"$SSH_PASS\" | sudo -S whois $h > $REMOTE_DIR/whois_$h.txt 2>/dev/null"
        log "WHOIS exit code: $?"

    done


    ##################################################################
    # 6. Permissions fix - not fully working
    ##################################################################
    log "Applying chmod -R 755 to remote workspace."

    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S chmod -R 755 $REMOTE_DIR 2>/dev/null"
    log "chmod exit code: $?"


    ##################################################################
    # 7. Download results
    ##################################################################
    log "Downloading remote scan results via SCP."

    sshpass -p "$SSH_PASS" scp -r -o StrictHostKeyChecking=no -P "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_DIR/" >/dev/null 2>&1
    log "SCP exit code: $?"


    #
    # Fix local permissions
    #
    log "Setting ownership of local scan directory."

    chown -R "$REAL_UID:$REAL_GID" "$LOCAL_DIR"
    log "Local chown exit code: $?"


    ##################################################################
    # 8. Remote cleanup
    ##################################################################
    log "Removing remote directory: $REMOTE_DIR"

    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$REMOTE_USER@$REMOTE_HOST" \
        "echo \"$SSH_PASS\" | sudo -S rm -rf $REMOTE_DIR 2>/dev/null"
    log "Remote rm exit code: $?"


    log "Network scan completed — results saved in: $LOCAL_DIR"
}
########################################################
# GENERATE TEXT REPORT (FULL AUDIT LOGGING)
########################################################
GENERATE_REPORT() {

    log "GENERATE_REPORT() invoked — starting report generation."

    REPORT_MD="$SESSION_DIR/report.md"
    REPORT_TXT="$SESSION_DIR/report.txt"

    log "Report paths:"
    log "  Markdown: $REPORT_MD"
    log "  Text: $REPORT_TXT"

    echo -e "${GREEN}[REPORT] Building S10 Security Report...${RESET}"
    log "Building S10 Security Report..."


    ##########################################################
    # METADATA COLLECTION
    ##########################################################
    log "Collecting session metadata."

    SESSION_SIZE=$(du -sh "$SESSION_DIR" | awk '{print $1}')
    EXIT_SZ=$?
    log "Collected folder size: $SESSION_SIZE (exit $EXIT_SZ)"

    SESSION_START=$(head -n1 "$LOG_FILE" | cut -d']' -f1 | tr -d '[')
    log "Extracted session start timestamp: ${SESSION_START:-unknown}"

    SESSION_END=$(date)
    log "Session end timestamp: $SESSION_END"

    TOR_EXIT_IP=$(curl -s https://wtfismyip.com/text)
    log "TOR exit IP detected: ${TOR_EXIT_IP:-none}"


    ##########################################################
    # REMOTE SYSTEM INFO (cached earlier)
    ##########################################################
    log "Collecting remote system summary information."
    log "  Remote IP: $REMOTE_PUBLIC_IP"
    log "  Country: $REMOTE_COUNTRY"
    log "  Uptime: $REMOTE_UPTIME"

    REMOTE_SUM_IP="$REMOTE_PUBLIC_IP"
    REMOTE_SUM_COUNTRY="$REMOTE_COUNTRY"
    REMOTE_SUM_UPTIME="$REMOTE_UPTIME"


    ##########################################################
    # SCAN FILE COLLECTION
    ##########################################################
    log "Collecting scan directories."

    SCAN_DIRS=()
    while IFS= read -r d; do
        SCAN_DIRS+=("$d")
    done < <(find "$SESSION_DIR/extracted" -mindepth 1 -maxdepth 1 -type d | sort)
    log "Found ${#SCAN_DIRS[@]} scan directories."

    NMAP_FILES=()
    while IFS= read -r f; do
        NMAP_FILES+=("$f")
    done < <(find "$SESSION_DIR" -type f -name "*.nmap" | sort)
    log "Found ${#NMAP_FILES[@]} Nmap files."


    ##########################################################
    # BUILD REPORT
    ##########################################################
    log "Generating Markdown report."

    {
        echo "# S10 Network Security Scan Report"
        echo "### Automated reconnaissance summary"
        echo "---"
        echo "**Session:** \`$SESSION_NAME\`  "
        echo "**Directory:** \`$SESSION_DIR\`  "
        echo "**Started:** $SESSION_START  "
        echo "**Finished:** $SESSION_END  "
        echo "**Folder Size:** $SESSION_SIZE  "
        echo "**TOR Exit IP:** $TOR_EXIT_IP"
        echo ""
        echo "---"
        echo "## Remote System Information"
        echo "- **Public IP:** $REMOTE_SUM_IP"
        echo "- **Country:** $REMOTE_SUM_COUNTRY"
        echo "- **Uptime:** $REMOTE_SUM_UPTIME"
        echo ""
        echo "---"
        echo "## Scan Results Collected"

        if (( ${#SCAN_DIRS[@]} == 0 )); then
            echo "_No scan result folders found._"
        else
            for d in "${SCAN_DIRS[@]}"; do
                echo "- $(basename "$d")"
            done
        fi

        echo ""
        echo "---"
        echo "## Open Ports & Service Versions"
        echo ""

        if (( ${#NMAP_FILES[@]} == 0 )); then
            echo "_No Nmap results found._"
        else
            for f in "${NMAP_FILES[@]}"; do
                base=$(basename "$f")
                echo "### $base"
                echo ""

                log "Extracting open ports from $f"

                awk '
                    $2 == "open" {
                        port=$1; svc=$3; ver="";
                        for(i=4;i<=NF;i++) ver=ver" "$i
                        printf "- **%s** → %s %s\n", port, svc, ver
                    }
                ' "$f"

                echo ""
            done
        fi

        echo "---"
        echo "## Vulnerability Findings"
        echo ""

        if (( ${#NMAP_FILES[@]} == 0 )); then
            echo "_No Nmap files found._"
        else
            for f in "${NMAP_FILES[@]}"; do
                base=$(basename "$f")
                echo "### $base"
                echo ""

                log "Extracting vulnerability blocks from $f"

                vuln_block=$(awk '
                    /VULNERABLE/ {in_v=1}
                    /VULNERABLE/ {print; next}
                    in_v {
                        print
                        if ($0 ~ /^Host:|^PORT|^Nmap done|^[0-9]+\/(tcp|udp)/) in_v=0
                    }
                    ' "$f")

                if [[ -z "$vuln_block" ]]; then
                    echo "_No vulnerabilities detected by Nmap vuln scripts._"
                else
                    echo '```'
                    echo "$vuln_block"
                    echo '```'
                fi

                echo ""
            done
        fi

        echo "---"
        echo "## Recent Log Entries"
        echo '```'
        tail -n 40 "$LOG_FILE"
        echo '```'

    } > "$REPORT_MD"

    EXIT_MD=$?
    log "Markdown report generation exit code: $EXIT_MD"


    cp "$REPORT_MD" "$REPORT_TXT"
    EXIT_CP=$?
    log "Copied report.md → report.txt (exit $EXIT_CP)"


    echo -e "${GREEN}[REPORT] S10 Report Created:${RESET}"
    echo " - $REPORT_MD"
    echo " - $REPORT_TXT"
    log "Reports created successfully."


    # FIX OWNERSHIP OF REPORTS AND LOG FILES
    chown -R "$REAL_UID:$REAL_GID" "$SESSION_DIR"
    log "Ownership updated for session directory (exit $?)."

    log "GENERATE_REPORT() completed."
}
########################################################
# MENU 
########################################################
MAIN_MENU() {
    log "MAIN_MENU() invoked — displaying options."

    while true; do
        echo -e "${YELLOW}\n1) Scan a single remote IP${RESET}"
        echo -e "${YELLOW}2) Scan the remote network${RESET}"
        echo -e "${YELLOW}0) Exit${RESET}"
        read -rp "Choose: " c

        log "User selected menu option: ${c:-empty}"

        case "$c" in

            1)
                log "Menu selection 1: Starting REMOTE_SCAN_IP()"
                REMOTE_SCAN_IP
                log "REMOTE_SCAN_IP() completed."
                ;;

            2)
                log "Menu selection 2: Starting REMOTE_SCAN_NETWORK()"
                REMOTE_SCAN_NETWORK
                log "REMOTE_SCAN_NETWORK() completed."
                ;;

            0)
                log "Menu selection 0: Exiting MAIN_MENU()."
                return
                ;;

            *)
                echo "Invalid"
                log "Invalid menu selection: '$c'"
                ;;

        esac

    done
}

########################################################
# START
########################################################
START
