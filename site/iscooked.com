#!/usr/bin/env bash
# iscooked.com — Am I Cooked? Local AI Security Scanner
# https://iscooked.com | MIT License
#
# Scans your local AI setup for security and privacy risks.
# Runs locally. Sends nothing anywhere. Ever.

set -euo pipefail

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

VERSION="1.0.0"

# ─── Colors & Formatting ───────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

COOKED="${RED}${BOLD}🔥 COOKED${RESET}"
WARMING="${YELLOW}⚠  WARMING UP${RESET}"
SAFE="${GREEN}✅ SAFE${RESET}"

# ─── State ──────────────────────────────────────────────────────────────────────

TOTAL_CHECKS=0
COOKED_COUNT=0
WARMING_COUNT=0
SAFE_COUNT=0
SCORE=0

# ─── OS Detection ──────────────────────────────────────────────────────────────

OS_TYPE="linux"
case "$(uname -s)" in
    Darwin*) OS_TYPE="macos" ;;
    Linux*)  OS_TYPE="linux" ;;
esac

# ─── Helpers ────────────────────────────────────────────────────────────────────

banner() {
    echo ""
    echo -e "${RED}${BOLD}"
    cat << 'BANNER'
                    __            __       __
  _________  ____  / /_____  ____/ /  ____/ /_
 / ___/ __ \/ __ \/ //_/ _ \/ __  /  / ___/ __ \
/ /__/ /_/ / /_/ / ,< /  __/ /_/ /_ (__  ) / / /
\___/\____/\____/_/|_|\___/\__,_/(_)____/_/ /_/

BANNER
    echo -e "${RESET}"
    echo -e "${DIM}  Am I Cooked? — Local AI Security Scanner v${VERSION}${RESET}"
    echo -e "${DIM}  https://iscooked.com${RESET}"
    echo ""
    echo -e "  ${CYAN}${BOLD}Scanning your setup...${RESET}"
    echo ""
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
}

draw_line() {
    local i=0
    local line=""
    while [ "$i" -lt 56 ]; do
        line="${line}─"
        i=$((i + 1))
    done
    echo "$line"
}

section() {
    echo ""
    echo -e "  ${MAGENTA}${BOLD}[$1]${RESET} ${WHITE}${BOLD}$2${RESET}"
    echo -e "  ${DIM}$(draw_line)${RESET}"
}

result_cooked() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    COOKED_COUNT=$((COOKED_COUNT + 1))
    SCORE=$((SCORE + 10))
    printf '%b  %s\n' "  ${COOKED}" "$(sanitize_result_message "$1")"
}

result_warming() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    WARMING_COUNT=$((WARMING_COUNT + 1))
    SCORE=$((SCORE + 4))
    printf '%b  %s\n' "  ${WARMING}" "$(sanitize_result_message "$1")"
}

result_safe() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SAFE_COUNT=$((SAFE_COUNT + 1))
    printf '%b  %s\n' "  ${SAFE}" "$(sanitize_result_message "$1")"
}

result_skip() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    printf '%b  %s\n' "  ${DIM}⏭  SKIP${RESET}" "$(sanitize_result_message "$1")"
}

command_exists() {
    command -v "$1" &>/dev/null
}

sanitize_result_message() {
    # Result messages can include untrusted command output. Keep terminal
    # controls from being interpreted when printed.
    printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177'
}

# Portable stat: returns octal permission string (e.g. "755")
get_file_perms() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        stat -f '%Lp' "$1" 2>/dev/null || echo "000"
    else
        stat -c '%a' "$1" 2>/dev/null || echo "000"
    fi
}

# Portable stat: returns owner username
get_file_owner() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        stat -f '%Su' "$1" 2>/dev/null || echo "unknown"
    else
        stat -c '%U' "$1" 2>/dev/null || echo "unknown"
    fi
}

# Portable listening socket check: returns matching lines for a port
get_listen_line() {
    local port="$1"
    if command_exists ss; then
        ss -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true
    elif command_exists netstat; then
        if [[ "$OS_TYPE" == "macos" ]]; then
            netstat -an -ptcp 2>/dev/null | grep LISTEN | grep -E "[:\.]${port}([[:space:]]|$)" || true
        else
            netstat -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true
        fi
    else
        echo ""
    fi
}

# Extract the local bind host from ss/netstat output for this port.
get_listen_host() {
    local listen_line="$1"
    local port="$2"
    local host
    host=$(awk '{print $4}' <<< "$listen_line")

    if [[ "$OS_TYPE" == "macos" ]]; then
        host="${host%."${port}"}"
    else
        host="${host%:"${port}"}"
    fi

    host="${host#[}"
    host="${host%]}"
    printf '%s\n' "$host"
}

is_all_interface_host() {
    local host="${1#[}"
    host="${host%]}"
    [[ "$host" == "0.0.0.0" || "$host" == "*" || "$host" == "::" ]]
}

is_loopback_host() {
    local host="${1#[}"
    host="${host%]}"
    [[ "$host" == "localhost" || "$host" == 127.* || "$host" == "::1" ]]
}

# Check if a listen line is bound to all interfaces
is_bound_all_interfaces() {
    local listen_line="$1"
    local port="$2"
    local line host
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        host=$(get_listen_host "$line" "$port")
        is_all_interface_host "$host" && return 0
    done <<< "$listen_line"
    return 1
}

is_bound_loopback_only() {
    local listen_line="$1"
    local port="$2"
    local line host found_loopback=false
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        host=$(get_listen_host "$line" "$port")
        if is_loopback_host "$host"; then
            found_loopback=true
        else
            return 1
        fi
    done <<< "$listen_line"
    [[ "$found_loopback" == "true" ]]
}

get_non_loopback_listen_host() {
    local listen_line="$1"
    local port="$2"
    local line host
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        host=$(get_listen_host "$line" "$port")
        if ! is_all_interface_host "$host" && ! is_loopback_host "$host"; then
            printf '%s\n' "$host"
            return 0
        fi
    done <<< "$listen_line"
    return 1
}

format_http_host() {
    local host="$1"
    if [[ "$host" == *:* && "$host" != \[*\] ]]; then
        printf '[%s]\n' "$host"
    else
        printf '%s\n' "$host"
    fi
}

# ─── Checks ─────────────────────────────────────────────────────────────────────

check_network_exposure() {
    section "01" "Network Exposure"

    local ai_ports=""
    ai_ports="11434:Ollama
8080:LM Studio / text-gen-webui
5000:text-gen-webui (alt)
7860:Gradio / Stable Diffusion WebUI
8188:ComfyUI
3000:Open WebUI
1234:LM Studio (alt)
8000:vLLM / FastChat
5001:LocalAI
9090:Prometheus (AI metrics)"

    local found_any=false

    while IFS= read -r entry; do
        local port="${entry%%:*}"
        local name="${entry#*:}"

        local listen_line=""
        listen_line=$(get_listen_line "$port")

        if [[ -n "$listen_line" ]]; then
            found_any=true
            if is_bound_all_interfaces "$listen_line" "$port"; then
                result_cooked "${name} (port ${port}) is listening on ALL interfaces"
            elif is_bound_loopback_only "$listen_line" "$port"; then
                result_safe "${name} (port ${port}) is bound to localhost only"
            else
                local bind_host
                bind_host=$(get_non_loopback_listen_host "$listen_line" "$port" || echo "non-loopback interface")
                result_warming "${name} (port ${port}) is bound to non-loopback interface ${bind_host}"
            fi
        fi
    done <<< "$ai_ports"

    if [[ "$found_any" == "false" ]]; then
        result_safe "No common AI service ports detected as listening"
    fi
}

check_api_auth() {
    section "02" "API Authentication"

    # Check Ollama
    if command_exists curl; then
        # Ollama
        local ollama_resp
        ollama_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 http://127.0.0.1:11434/ 2>/dev/null) || ollama_resp="000"
        if [[ "$ollama_resp" == "200" ]]; then
            result_warming "Ollama API is responding without authentication"
        elif [[ "$ollama_resp" != "000" ]]; then
            result_safe "Ollama API returned ${ollama_resp} (not open)"
        fi

        # LM Studio
        local lms_resp
        lms_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 http://127.0.0.1:1234/v1/models 2>/dev/null) || lms_resp="000"
        if [[ "$lms_resp" == "200" ]]; then
            result_warming "LM Studio API is responding without authentication"
        fi

        # Open WebUI
        local webui_resp
        webui_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 http://127.0.0.1:3000/ 2>/dev/null) || webui_resp="000"
        if [[ "$webui_resp" == "200" ]]; then
            result_warming "Open WebUI is accessible without checking for auth"
        fi
    else
        result_skip "curl not found, skipping API auth checks"
    fi
}

check_model_permissions() {
    section "03" "Model File Permissions"

    local found_models=false

    # Build list of model dirs based on OS
    local model_dirs_list=""
    model_dirs_list="$HOME/.ollama/models
$HOME/.cache/lm-studio/models
$HOME/.cache/huggingface/hub
$HOME/models
$HOME/.local/share/nomic.ai
/usr/share/ollama/.ollama/models"

    if [[ "$OS_TYPE" == "macos" ]]; then
        model_dirs_list="$model_dirs_list
$HOME/Library/Application Support/LM Studio/models
$HOME/.lmstudio/models"
        # Add Homebrew Ollama path if brew exists
        if command_exists brew; then
            local brew_prefix
            brew_prefix=$(brew --prefix 2>/dev/null || echo "")
            if [[ -n "$brew_prefix" ]]; then
                model_dirs_list="$model_dirs_list
${brew_prefix}/var/ollama/models"
            fi
        fi
    fi

    while IFS= read -r dir; do
        if [[ -d "$dir" ]]; then
            found_models=true
            # Check if world-readable
            local world_readable
            world_readable=$(find "$dir" -type f -perm -o+r 2>/dev/null | head -5 || true)
            if [[ -n "$world_readable" ]]; then
                result_warming "Model directory ${dir} is world-readable"
            else
                result_safe "Model directory ${dir} has restrictive permissions"
            fi

            # Check if world-writable
            local world_writable
            world_writable=$(find "$dir" -maxdepth 2 -perm -o+w 2>/dev/null | head -5 || true)
            if [[ -n "$world_writable" ]]; then
                result_cooked "Files in ${dir} are world-writable!"
            fi
        fi
    done <<< "$model_dirs_list"

    if [[ "$found_models" == "false" ]]; then
        result_skip "No common model directories found"
    fi
}

check_docker_risks() {
    section "04" "Docker / Container Risks"

    if ! command_exists docker; then
        result_skip "Docker not installed, skipping container checks"
        return
    fi

    # Check if docker daemon is reachable
    if ! docker info &>/dev/null; then
        result_skip "Docker daemon not reachable (not running or no permissions)"
        return
    fi

    local ai_containers
    ai_containers=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE 'ollama|llama|text-gen|webui|comfy|vllm|localai|stable|diffusion|lmstudio|open-webui|litellm' || true)

    if [[ -z "$ai_containers" ]]; then
        result_skip "No AI-related containers running"
        return
    fi

    while IFS= read -r container_line; do
        local cname
        cname=$(echo "$container_line" | awk '{print $1}')

        # Check if running as root
        local user
        user=$(docker inspect --format '{{.Config.User}}' "$cname" 2>/dev/null || echo "")
        if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            result_cooked "Container '${cname}' is running as root"
        else
            result_safe "Container '${cname}' is running as user '${user}'"
        fi

        # Check privileged mode
        local privileged
        privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cname" 2>/dev/null || echo "false")
        if [[ "$privileged" == "true" ]]; then
            result_cooked "Container '${cname}' is running in PRIVILEGED mode"
        fi

        # Check host network
        local network
        network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null || echo "")
        if [[ "$network" == "host" ]]; then
            result_warming "Container '${cname}' is using host networking"
        fi

        # Check mounted volumes for sensitive paths
        local mounts
        mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cname" 2>/dev/null || echo "")
        if echo "$mounts" | grep -qE '(/etc|/root|/home/[^/]+$)'; then
            result_warming "Container '${cname}' has sensitive host paths mounted"
        fi

    done <<< "$ai_containers"
}

check_gpu_exposure() {
    section "05" "GPU Driver Exposure"

    local found_gpu=false

    # NVIDIA (Linux)
    if command_exists nvidia-smi; then
        found_gpu=true
        # Check if nvidia management services have exposed ports
        local nvidia_listen=""
        nvidia_listen=$(get_listen_line "" 2>/dev/null || true)
        # More targeted check: look for nvidia-related listeners
        if command_exists ss; then
            nvidia_listen=$(ss -tlnp 2>/dev/null | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
        elif command_exists netstat; then
            if [[ "$OS_TYPE" == "macos" ]]; then
                nvidia_listen=$(netstat -an -ptcp 2>/dev/null | grep LISTEN | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
            else
                nvidia_listen=$(netstat -tlnp 2>/dev/null | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
            fi
        fi

        if [[ -n "$nvidia_listen" ]]; then
            result_warming "NVIDIA management service has network-exposed ports"
        else
            result_safe "NVIDIA GPU detected, no management ports exposed"
        fi

        # Check nvidia device permissions (Linux only)
        if [[ "$OS_TYPE" == "linux" && -e /dev/nvidia0 ]]; then
            local nv_perms
            nv_perms=$(get_file_perms /dev/nvidia0)
            if [[ "${nv_perms: -1}" -ge 6 ]]; then
                result_warming "/dev/nvidia0 is accessible to all users (mode ${nv_perms})"
            else
                result_safe "/dev/nvidia0 has restrictive permissions (mode ${nv_perms})"
            fi
        fi
    fi

    # AMD ROCm (Linux only)
    if [[ "$OS_TYPE" == "linux" && -d /dev/dri ]]; then
        found_gpu=true
        if [[ -e /dev/dri/renderD128 ]]; then
            local render_perms
            render_perms=$(get_file_perms /dev/dri/renderD128)
            if [[ "${render_perms: -1}" -ge 6 ]]; then
                result_warming "/dev/dri/renderD128 is world-accessible (mode ${render_perms})"
            fi
        fi
    fi

    # macOS GPU — Metal is sandboxed, but check for external GPU access
    if [[ "$OS_TYPE" == "macos" ]]; then
        if system_profiler SPDisplaysDataType 2>/dev/null | grep -qi "Metal\|GPU"; then
            found_gpu=true
            result_safe "macOS GPU uses Metal (sandboxed by default)"
        fi
    fi

    if [[ "$found_gpu" == "false" ]]; then
        result_skip "No GPU devices detected"
    fi
}

check_telemetry() {
    section "06" "Telemetry / Phoning Home"

    local telemetry_domains_list="telemetry.ollama.ai
telemetry.vllm.ai
sentry.io
segment.io
amplitude.com
mixpanel.com
analytics.google.com
stats.lmstudio.ai"

    # Check active connections
    local active_conns=""
    if command_exists ss; then
        active_conns=$(ss -tnp 2>/dev/null || true)
    elif command_exists netstat; then
        active_conns=$(netstat -tn 2>/dev/null || true)
    fi

    # Check if OLLAMA_NO_CLOUD or telemetry opt-outs are set
    if [[ -n "${OLLAMA_NO_CLOUD:-}" ]]; then
        result_safe "OLLAMA_NO_CLOUD is set"
    fi

    local do_not_track="${DO_NOT_TRACK:-}"
    if [[ "$do_not_track" == "1" ]]; then
        result_safe "DO_NOT_TRACK=1 is set (good!)"
    else
        result_warming "DO_NOT_TRACK is not set — some tools respect this env var"
    fi

    # Check /etc/hosts for blocked telemetry
    if [[ -f /etc/hosts ]]; then
        local blocked=0
        while IFS= read -r domain; do
            if grep -qE "^\\s*0\\.0\\.0\\.0\\s+${domain}$" /etc/hosts 2>/dev/null; then
                blocked=$((blocked + 1))
            fi
        done <<< "$telemetry_domains_list"
        if [[ $blocked -gt 0 ]]; then
            result_safe "${blocked} telemetry domains blocked in /etc/hosts"
        fi
    fi

}

check_firewall() {
    section "07" "Firewall Status"

    local has_firewall=false

    if [[ "$OS_TYPE" == "macos" ]]; then
        # macOS Application Firewall (socketfilterfw)
        if command_exists /usr/libexec/ApplicationFirewall/socketfilterfw; then
            local fw_status
            fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "disabled")
            if echo "$fw_status" | grep -qi "enabled"; then
                result_safe "macOS Application Firewall is enabled"
                has_firewall=true
            else
                result_cooked "macOS Application Firewall is DISABLED"
            fi
        fi

        # macOS pf (packet filter)
        if command_exists pfctl; then
            local pf_status
            pf_status=$(pfctl -s info 2>/dev/null || echo "disabled")
            if echo "$pf_status" | grep -qi "Status: Enabled"; then
                result_safe "macOS pf (packet filter) is enabled"
                has_firewall=true
            fi
        fi
    else
        # UFW
        if command_exists ufw; then
            local ufw_status
            ufw_status=$(ufw status 2>/dev/null || echo "inactive")
            if echo "$ufw_status" | grep -Eqi "^Status:[[:space:]]+active$"; then
                result_safe "UFW firewall is active"
                has_firewall=true
            else
                result_cooked "UFW is installed but INACTIVE"
            fi
        fi

        # firewalld
        if command_exists firewall-cmd; then
            if firewall-cmd --state &>/dev/null; then
                result_safe "firewalld is active"
                has_firewall=true
            else
                result_cooked "firewalld is installed but INACTIVE"
            fi
        fi

        # iptables — check if any rules exist
        if command_exists iptables; then
            local rule_count
            rule_count=$(iptables -L 2>/dev/null | grep -c -v -E "^Chain|^target|^$" || echo "0")
            rule_count=$((rule_count + 0))
            if [[ "$rule_count" -gt 2 ]]; then
                result_safe "iptables has ${rule_count} rules configured"
                has_firewall=true
            elif [[ "$has_firewall" == "false" ]]; then
                result_warming "iptables has minimal/no rules"
            fi
        fi

        # nftables
        if command_exists nft; then
            local nft_rules
            nft_rules=$(nft list ruleset 2>/dev/null | wc -l || echo "0")
            nft_rules=$((nft_rules + 0))
            if [[ "$nft_rules" -gt 5 ]]; then
                result_safe "nftables has rules configured"
                has_firewall=true
            fi
        fi
    fi

    if [[ "$has_firewall" == "false" ]]; then
        result_cooked "No active firewall detected!"
    fi
}

check_ssl_tls() {
    section "08" "SSL/TLS Configuration"

    local ports_list="11434
8080
5000
7860
8188
3000
1234
8000"
    local found_http=false

    while IFS= read -r port; do
        local listen_line=""
        listen_line=$(get_listen_line "$port")

        if [[ -n "$listen_line" ]]; then
            local probe_host=""
            local exposure_desc=""
            if is_bound_all_interfaces "$listen_line" "$port"; then
                probe_host="127.0.0.1"
                exposure_desc="all interfaces"
            else
                probe_host=$(get_non_loopback_listen_host "$listen_line" "$port" || true)
                exposure_desc="$probe_host"
            fi

            if [[ -n "$probe_host" ]]; then
                if command_exists curl; then
                    local http_code
                    local probe_url_host
                    probe_url_host=$(format_http_host "$probe_host")
                    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 "http://${probe_url_host}:${port}/" 2>/dev/null) || http_code="000"
                    if [[ "$http_code" != "000" && -n "$http_code" ]]; then
                        result_cooked "Port ${port} is exposed on ${exposure_desc} over plain HTTP"
                        found_http=true
                    fi
                else
                    result_warming "Port ${port} is exposed on ${exposure_desc} (cannot verify TLS without curl)"
                    found_http=true
                fi
            fi
        fi
    done <<< "$ports_list"

    if [[ "$found_http" == "false" ]]; then
        result_safe "No AI services exposed over plain HTTP on non-localhost"
    fi
}

check_processes() {
    section "09" "AI Process Enumeration"

    local ai_process_patterns="ollama|llama\.cpp|llama-server|text-generation|vllm|lmstudio|comfyui|stable-diffusion|koboldcpp|localai|whisper|faster-whisper|tabbyAPI"

    local ai_procs
    local my_pid=$$
    ai_procs=$(ps aux 2>/dev/null | grep -iE "$ai_process_patterns" | awk -v pid="$my_pid" '$2 != pid {print}' || true)

    if [[ -z "$ai_procs" ]]; then
        result_skip "No AI-related processes running"
        return
    fi

    while IFS= read -r proc_line; do
        local proc_user proc_cmd
        proc_user=$(echo "$proc_line" | awk '{print $1}')
        proc_cmd=$(echo "$proc_line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | head -c 60)

        if [[ "$proc_user" == "root" ]]; then
            result_cooked "AI process running as root: ${proc_cmd}"
        else
            result_safe "AI process running as '${proc_user}': ${proc_cmd}"
        fi
    done <<< "$ai_procs"
}

check_sensitive_files() {
    section "10" "Sensitive File Exposure"

    # Check .env files in common locations
    local search_dirs_list="$HOME
$HOME/Projects
$HOME/projects
$HOME/code
$HOME/dev
/opt
/srv"

    local found_exposed_env=false
    while IFS= read -r dir; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r env_file; do
                [[ -z "$env_file" ]] && continue
                if [[ -f "$env_file" ]]; then
                    local perms
                    perms=$(get_file_perms "$env_file")
                    if [[ "${perms: -1}" -ge 4 ]]; then
                        if grep -qiE '(api_key|api_secret|token|password|secret)=' "$env_file" 2>/dev/null; then
                            result_cooked ".env file with API keys is world-readable: ${env_file} (mode ${perms})"
                            found_exposed_env=true
                        fi
                    fi
                fi
            done < <(find "$dir" -maxdepth 3 -name ".env" -o -name ".env.local" -o -name "*.env" 2>/dev/null | head -20 || true)
        fi
    done <<< "$search_dirs_list"

    if [[ "$found_exposed_env" == "false" ]]; then
        result_safe "No world-readable .env files with API keys found"
    fi

    # Check if models directory is owned properly
    if [[ -d "$HOME/.ollama" ]]; then
        local ollama_owner
        ollama_owner=$(get_file_owner "$HOME/.ollama")
        if [[ "$ollama_owner" != "$(whoami)" && "$ollama_owner" != "ollama" ]]; then
            result_warming "~/.ollama is owned by '${ollama_owner}' instead of you"
        fi
    fi
}

check_history_logs() {
    section "11" "History & Logs Leakage"

    # Check shell history for API keys
    local history_files_list="$HOME/.bash_history
$HOME/.zsh_history
$HOME/.local/share/fish/fish_history"

    while IFS= read -r hist_file; do
        if [[ -f "$hist_file" ]]; then
            local key_leaks
            key_leaks=$(grep -ciE '(sk-[a-zA-Z0-9]{20,}|api_key=|OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN)' "$hist_file" 2>/dev/null || true)
            key_leaks="${key_leaks:-0}"
            if [[ "$key_leaks" -gt 0 ]]; then
                result_cooked "Shell history contains ~${key_leaks} potential API key(s): $(basename "$hist_file")"
            else
                result_safe "No API keys found in $(basename "$hist_file")"
            fi

            # Check permissions on history file
            local hist_perms
            hist_perms=$(get_file_perms "$hist_file")
            if [[ "${hist_perms: -1}" -ge 4 ]]; then
                result_warming "$(basename "$hist_file") is world-readable (mode ${hist_perms})"
            fi
        fi
    done <<< "$history_files_list"

    # Check common AI log locations
    local log_dirs_list="$HOME/.ollama/logs
$HOME/.cache/lm-studio/logs
/var/log/ollama"

    # Add macOS-specific log locations
    if [[ "$OS_TYPE" == "macos" ]]; then
        log_dirs_list="$log_dirs_list
$HOME/Library/Logs/LM Studio"
    fi

    while IFS= read -r log_dir; do
        if [[ -d "$log_dir" ]]; then
            local log_perms
            log_perms=$(get_file_perms "$log_dir")
            if [[ "${log_perms: -1}" -ge 4 ]]; then
                result_warming "AI log directory is world-readable: ${log_dir}"
            else
                result_safe "AI log directory has restrictive permissions: ${log_dir}"
            fi
        fi
    done <<< "$log_dirs_list"
}

check_ollama_config() {
    section "12" "Ollama-Specific Checks"

    if ! command_exists ollama; then
        result_skip "Ollama not installed"
        return
    fi

    # Check OLLAMA_HOST
    local ollama_host="${OLLAMA_HOST:-}"
    if [[ -n "$ollama_host" ]]; then
        if echo "$ollama_host" | grep -qE '^0\.0\.0\.0|^::'; then
            result_cooked "OLLAMA_HOST is set to ${ollama_host} — exposed to network!"
        elif echo "$ollama_host" | grep -qE '^127\.|^localhost'; then
            result_safe "OLLAMA_HOST is bound to localhost (${ollama_host})"
        else
            result_warming "OLLAMA_HOST is set to ${ollama_host} — verify this is intentional"
        fi
    else
        result_safe "OLLAMA_HOST not set (defaults to localhost)"
    fi

    # Check OLLAMA_ORIGINS
    local ollama_origins="${OLLAMA_ORIGINS:-}"
    if [[ "$ollama_origins" == "*" ]]; then
        result_cooked "OLLAMA_ORIGINS=* — any website can access your Ollama!"
    elif [[ -n "$ollama_origins" ]]; then
        result_warming "OLLAMA_ORIGINS is set to: ${ollama_origins}"
    fi

    # Check systemd service file (Linux only)
    if [[ "$OS_TYPE" == "linux" && -f /etc/systemd/system/ollama.service ]]; then
        local svc_user
        svc_user=$(grep -oP 'User=\K.*' /etc/systemd/system/ollama.service 2>/dev/null || echo "")
        if [[ "$svc_user" == "root" || -z "$svc_user" ]]; then
            result_warming "Ollama systemd service runs as root (or no User= set)"
        else
            result_safe "Ollama systemd service runs as '${svc_user}'"
        fi
    fi

    # macOS: check Homebrew Ollama
    if [[ "$OS_TYPE" == "macos" ]]; then
        if command_exists brew; then
            local brew_prefix
            brew_prefix=$(brew --prefix 2>/dev/null || echo "")
            if [[ -n "$brew_prefix" && -d "${brew_prefix}/opt/ollama" ]]; then
                result_safe "Ollama installed via Homebrew at ${brew_prefix}/opt/ollama"
            fi
        fi
        # Check launchctl for Ollama service
        if launchctl list 2>/dev/null | grep -qi ollama; then
            result_safe "Ollama is registered as a launchctl service"
        fi
    fi
}

# ─── Score & Summary ────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
    echo ""

    # Cap score at 100
    if [[ $SCORE -gt 100 ]]; then
        SCORE=100
    fi

    # Determine cooked level
    local level_text level_color bar_char
    if [[ $SCORE -ge 70 ]]; then
        level_text="FULLY COOKED"
        level_color="$RED"
        bar_char="█"
    elif [[ $SCORE -ge 40 ]]; then
        level_text="MEDIUM RARE"
        level_color="$YELLOW"
        bar_char="▓"
    elif [[ $SCORE -ge 15 ]]; then
        level_text="SLIGHTLY WARM"
        level_color="$CYAN"
        bar_char="▒"
    else
        level_text="LOOKING FRESH"
        level_color="$GREEN"
        bar_char="░"
    fi

    # Score bar
    local bar_width=40
    local filled=$((SCORE * bar_width / 100))
    local empty=$((bar_width - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="$bar_char"; done
    for ((i=0; i<empty; i++)); do bar+=" "; done

    echo -e "  ${WHITE}${BOLD}YOUR COOKED SCORE${RESET}"
    echo ""
    echo -e "  ${level_color}${BOLD}${SCORE}%${RESET} ${DIM}cooked${RESET}  [${level_color}${bar}${RESET}]"
    echo ""
    echo -e "  ${level_color}${BOLD}${level_text}${RESET}"
    echo ""
    echo -e "  ${RED}${BOLD}${COOKED_COUNT}${RESET} critical  ${YELLOW}${BOLD}${WARMING_COUNT}${RESET} warnings  ${GREEN}${BOLD}${SAFE_COUNT}${RESET} passed  ${DIM}(${TOTAL_CHECKS} total checks)${RESET}"
    echo ""

    if [[ $SCORE -ge 70 ]]; then
        echo -e "  ${RED}You are absolutely cooked. Fix the critical issues above ASAP.${RESET}"
    elif [[ $SCORE -ge 40 ]]; then
        echo -e "  ${YELLOW}You're getting warm. Address the warnings to tighten things up.${RESET}"
    elif [[ $SCORE -ge 15 ]]; then
        echo -e "  ${CYAN}Not bad! A few things to clean up but you're mostly good.${RESET}"
    else
        echo -e "  ${GREEN}Looking fresh! Your local AI setup is pretty well locked down.${RESET}"
    fi

    echo ""
    echo -e "  ${DIM}Elevated privileges can improve some firewall and port checks.${RESET}"
    echo -e "  ${DIM}Report issues: https://github.com/johnpippett/iscooked${RESET}"
    echo ""
}

# ─── Main ───────────────────────────────────────────────────────────────────────

main() {
    banner

    check_network_exposure
    check_api_auth
    check_model_permissions
    check_docker_risks
    check_gpu_exposure
    check_telemetry
    check_firewall
    check_ssl_tls
    check_processes
    check_sensitive_files
    check_history_logs
    check_ollama_config

    print_summary
}

main "$@"
