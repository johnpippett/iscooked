#!/usr/bin/env bash
# iscooked.com — Am I Cooked? AI & Coding Agent Security Scanner
# https://iscooked.com | MIT License
#
# Examines coding agent and local AI setups for security and privacy risks.
# Reports stay local. Selected probes read service metadata.

set -euo pipefail

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

VERSION="1.4.0"

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
UNKNOWN="${CYAN}❓ UNKNOWN${RESET}"

# ─── State ──────────────────────────────────────────────────────────────────────

TOTAL_CHECKS=0
COOKED_COUNT=0
WARMING_COUNT=0
SAFE_COUNT=0
UNKNOWN_COUNT=0
SKIPPED_COUNT=0
SCORE=0
OUTPUT_FORMAT=text
FAIL_ON=none
COLOR_MODE=auto
FULL_SCAN=false
PROBLEMS_ONLY=false
ONLY_CHECKS=""
SKIP_CHECKS=""
DIFF_FILE=""
DIFF_JSON=""
SECTION_PRINTED=false
CURRENT_CHECK_ID=""
CURRENT_CHECK_TITLE=""
CURRENT_AREA_INDEX=-1
STARTED_AREA_COUNT=0
STARTED_AREA_IDS=()
STARTED_AREA_TITLES=()
AREA_OBSERVATION_FLAGS=()
AREA_UNKNOWN_FLAGS=()
AREA_SKIP_FLAGS=()
FINDING_CHECK_IDS=()
FINDING_CHECK_TITLES=()
FINDING_STATUSES=()
FINDING_MESSAGES=()
FINDING_POINTS=()
FINDING_HINTS=()
EXPOSED_CRITICAL_PORTS=()

# ─── OS Detection ──────────────────────────────────────────────────────────────

OS_TYPE="unsupported"
case "$(uname -s)" in
    Darwin*) OS_TYPE="macos" ;;
    Linux*)  OS_TYPE="linux" ;;
esac
if [[ "$OS_TYPE" == macos ]]; then
    PATH="/opt/homebrew/sbin:/opt/homebrew/bin:$PATH"
fi

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
    echo -e "${DIM}  Am I Cooked? — AI & Coding Agent Security Scanner v${VERSION}${RESET}"
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

print_section_header() {
    echo ""
    echo -e "  ${MAGENTA}${BOLD}[${CURRENT_CHECK_ID}]${RESET} ${WHITE}${BOLD}${CURRENT_CHECK_TITLE}${RESET}"
    echo -e "  ${DIM}$(draw_line)${RESET}"
}

section() {
    local same_area=false area_index
    if [[ "$CURRENT_CHECK_ID" == "$1" && "$CURRENT_CHECK_TITLE" == "$2" && "$CURRENT_AREA_INDEX" -ge 0 ]]; then
        same_area=true
    fi
    CURRENT_CHECK_ID="$1"
    CURRENT_CHECK_TITLE="$2"
    if [[ "$same_area" == false ]]; then
        CURRENT_AREA_INDEX=-1
        if [[ "${#STARTED_AREA_IDS[@]}" -gt 0 ]]; then
            for area_index in "${!STARTED_AREA_IDS[@]}"; do
                if [[ "${STARTED_AREA_IDS[area_index]}" == "$1" ]]; then
                    CURRENT_AREA_INDEX="$area_index"
                    break
                fi
            done
        fi
        if [[ "$CURRENT_AREA_INDEX" -lt 0 ]]; then
            CURRENT_AREA_INDEX="$STARTED_AREA_COUNT"
            STARTED_AREA_IDS[CURRENT_AREA_INDEX]="$1"
            STARTED_AREA_TITLES[CURRENT_AREA_INDEX]="$2"
            AREA_OBSERVATION_FLAGS[CURRENT_AREA_INDEX]=0
            AREA_UNKNOWN_FLAGS[CURRENT_AREA_INDEX]=0
            AREA_SKIP_FLAGS[CURRENT_AREA_INDEX]=0
            STARTED_AREA_COUNT=$((STARTED_AREA_COUNT + 1))
        fi
        SECTION_PRINTED=false
    fi
    [[ "$same_area" == true ]] && return 0
    [[ "$OUTPUT_FORMAT" == text ]] || return 0
    [[ "$PROBLEMS_ONLY" == false ]] || return 0
    print_section_header
    SECTION_PRINTED=true
}

check_area_metadata() {
    case "$1" in
        check_network_exposure) CHECK_METADATA_ID="01"; CHECK_METADATA_TITLE="Network Exposure" ;;
        check_api_auth) CHECK_METADATA_ID="02"; CHECK_METADATA_TITLE="API Authentication" ;;
        check_model_permissions) CHECK_METADATA_ID="03"; CHECK_METADATA_TITLE="Model File Permissions" ;;
        check_docker_risks) CHECK_METADATA_ID="04"; CHECK_METADATA_TITLE="Docker / Container Risks" ;;
        check_gpu_exposure) CHECK_METADATA_ID="05"; CHECK_METADATA_TITLE="GPU Driver Exposure" ;;
        check_telemetry) CHECK_METADATA_ID="06"; CHECK_METADATA_TITLE="Telemetry / Phoning Home" ;;
        check_firewall) CHECK_METADATA_ID="07"; CHECK_METADATA_TITLE="Firewall Status" ;;
        check_ssl_tls) CHECK_METADATA_ID="08"; CHECK_METADATA_TITLE="SSL/TLS Configuration" ;;
        check_processes) CHECK_METADATA_ID="09"; CHECK_METADATA_TITLE="AI Process Enumeration" ;;
        check_sensitive_files) CHECK_METADATA_ID="10"; CHECK_METADATA_TITLE="Sensitive File Exposure" ;;
        check_history_logs) CHECK_METADATA_ID="11"; CHECK_METADATA_TITLE="History & Logs Leakage" ;;
        check_ollama_config) CHECK_METADATA_ID="12"; CHECK_METADATA_TITLE="Ollama-Specific Checks" ;;
        check_browser_debugging) CHECK_METADATA_ID="13"; CHECK_METADATA_TITLE="Browser Remote Debugging" ;;
        check_mcp_config) CHECK_METADATA_ID="14"; CHECK_METADATA_TITLE="MCP Configuration" ;;
        check_agent_gateway) CHECK_METADATA_ID="15"; CHECK_METADATA_TITLE="Coding Agent Permissions & Gateways" ;;
        check_model_code_execution) CHECK_METADATA_ID="16"; CHECK_METADATA_TITLE="Remote Model Code" ;;
        check_runtime_versions) CHECK_METADATA_ID="17"; CHECK_METADATA_TITLE="Runtime Versions" ;;
        *) return 2 ;;
    esac
}

resolve_check_token() {
    case "$1" in
        01|1|network|network_exposure) printf '01' ;;
        02|2|api|api_auth|auth) printf '02' ;;
        03|3|models|model_permissions) printf '03' ;;
        04|4|docker|containers|docker_risks) printf '04' ;;
        05|5|gpu|gpu_exposure) printf '05' ;;
        06|6|telemetry) printf '06' ;;
        07|7|firewall) printf '07' ;;
        08|8|ssl|tls|ssl_tls) printf '08' ;;
        09|9|processes|procs) printf '09' ;;
        10|sensitive|files|env|sensitive_files) printf '10' ;;
        11|history|logs|history_logs) printf '11' ;;
        12|ollama|ollama_config) printf '12' ;;
        13|browser|browser_debugging) printf '13' ;;
        14|mcp|mcp_config) printf '14' ;;
        15|agents|agent|gateway|agent_gateway) printf '15' ;;
        16|model-code|model_code|remote-code|model_code_execution) printf '16' ;;
        17|versions|runtime|runtime_versions) printf '17' ;;
        *) return 2 ;;
    esac
}

parse_check_list() {
    local csv="$1" token resolved out="" IFS=','
    [[ -n "$csv" ]] || return 2
    for token in $csv; do
        [[ -n "$token" ]] || return 2
        resolved=$(resolve_check_token "$token") || return 2
        out="${out:+${out},}${resolved}"
    done
    printf '%s' "$out"
}

check_selected() {
    local id="$1" item matched=false
    if [[ -n "$ONLY_CHECKS" ]]; then
        local IFS=','
        for item in $ONLY_CHECKS; do
            if [[ "$item" == "$id" ]]; then
                matched=true
                break
            fi
        done
        [[ "$matched" == true ]] || return 1
    fi
    if [[ -n "$SKIP_CHECKS" ]]; then
        local IFS=','
        for item in $SKIP_CHECKS; do
            if [[ "$item" == "$id" ]]; then
                return 1
            fi
        done
    fi
    return 0
}

is_exposed_critical_port() {
    local target="$1" port
    if [[ "${#EXPOSED_CRITICAL_PORTS[@]}" -gt 0 ]]; then
        for port in "${EXPOSED_CRITICAL_PORTS[@]}"; do
            if [[ "$port" == "$target" ]]; then
                return 0
            fi
        done
    fi
    return 1
}

run_check() {
    local check_name="$1" results_before
    check_area_metadata "$check_name"
    if ! check_selected "$CHECK_METADATA_ID"; then
        return 0
    fi
    section "$CHECK_METADATA_ID" "$CHECK_METADATA_TITLE"
    results_before=$TOTAL_CHECKS
    "$check_name"
    if [[ "$TOTAL_CHECKS" -eq "$results_before" ]]; then
        result_skip "No result was reported by this check; inspection is incomplete"
    fi
}

result_cooked() {
    record_result critical "$1" "${2:-}"
}

result_warming() {
    record_result warning "$1" "${2:-}"
}

result_safe() {
    record_result passed "$1" "${2:-}"
}

result_skip() {
    record_result skipped "$1" "${2:-}"
}

result_unknown() {
    record_result unknown "$1" "${2:-}"
}

record_result() {
    local status="$1" message hint points=0 label
    message=$(sanitize_result_message "$2")
    hint=$(sanitize_result_message "${3:-}")
    case "$status" in
        critical) COOKED_COUNT=$((COOKED_COUNT + 1)); points=10; label="$COOKED" ;;
        warning) WARMING_COUNT=$((WARMING_COUNT + 1)); points=4; label="$WARMING" ;;
        passed) SAFE_COUNT=$((SAFE_COUNT + 1)); label="$SAFE" ;;
        unknown) UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1)); points=0; label="$UNKNOWN" ;;
        skipped) SKIPPED_COUNT=$((SKIPPED_COUNT + 1)); label="${DIM}⏭  SKIP${RESET}" ;;
        *) return 2 ;;
    esac
    if [[ -n "${4:-}" ]]; then
        points="$4"
    fi
    FINDING_CHECK_IDS[TOTAL_CHECKS]="$CURRENT_CHECK_ID"
    FINDING_CHECK_TITLES[TOTAL_CHECKS]="$CURRENT_CHECK_TITLE"
    FINDING_STATUSES[TOTAL_CHECKS]="$status"
    FINDING_MESSAGES[TOTAL_CHECKS]="$message"
    FINDING_POINTS[TOTAL_CHECKS]="$points"
    FINDING_HINTS[TOTAL_CHECKS]="$hint"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SCORE=$((SCORE + points))
    if [[ "$CURRENT_AREA_INDEX" -ge 0 ]]; then
        case "$status" in
            critical|warning|passed) AREA_OBSERVATION_FLAGS[CURRENT_AREA_INDEX]=1 ;;
            unknown) AREA_UNKNOWN_FLAGS[CURRENT_AREA_INDEX]=1 ;;
            skipped) AREA_SKIP_FLAGS[CURRENT_AREA_INDEX]=1 ;;
        esac
    fi
    if [[ "$OUTPUT_FORMAT" == text ]]; then
        if [[ "$PROBLEMS_ONLY" == false || "$status" == critical || "$status" == warning || "$status" == unknown ]]; then
            if [[ "$SECTION_PRINTED" == false ]]; then
                print_section_header
                SECTION_PRINTED=true
            fi
            printf '%b  %s\n' "  ${label}" "$message"
            if [[ -n "$hint" && "$status" != passed ]]; then
                printf '      %b\n' "${DIM}↳ ${hint}${RESET}"
            fi
        fi
    fi
}

coverage_count() {
    local kind="$1" area_index flag count=0
    if [[ "${#STARTED_AREA_IDS[@]}" -gt 0 ]]; then
        for area_index in "${!STARTED_AREA_IDS[@]}"; do
            case "$kind" in
                observations) flag="${AREA_OBSERVATION_FLAGS[area_index]:-0}" ;;
                unknown) flag="${AREA_UNKNOWN_FLAGS[area_index]:-0}" ;;
                skips) flag="${AREA_SKIP_FLAGS[area_index]:-0}" ;;
                *) return 2 ;;
            esac
            if [[ "$flag" == 1 ]]; then
                count=$((count + 1))
            fi
        done
    fi
    printf '%s' "$count"
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
        stat -f '%Lp' "$1" 2>/dev/null
    else
        stat -c '%a' "$1" 2>/dev/null
    fi
}

# Portable stat: returns owner username
get_file_owner() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        stat -f '%Su' "$1" 2>/dev/null
    else
        stat -c '%U' "$1" 2>/dev/null
    fi
}

# Linux fallback when ss and netstat are absent (minimal images, containers):
# read the kernel socket tables directly and print ss-style LISTEN lines so the
# existing host:port parsing applies. Process names are not available here.
proc_net_listen_lines() {
    local proc_net="${ISCOOKED_TEST_PROC_NET:-/proc/net}"
    [[ "$OS_TYPE" == "linux" && -r "$proc_net/tcp" ]] || return 1
    local tables=("$proc_net/tcp")
    [[ -r "$proc_net/tcp6" ]] && tables+=("$proc_net/tcp6")
    awk '
        function hex(s,    i, n) {
            n = 0
            for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789abcdef", substr(tolower(s), i, 1)) - 1
            return n
        }
        # Kernel addresses are 32-bit words in host (little-endian) byte order.
        function word_bytes(w) {
            return hex(substr(w, 7, 2)) "." hex(substr(w, 5, 2)) "." hex(substr(w, 3, 2)) "." hex(substr(w, 1, 2))
        }
        function v6(a,    i, b, g, out, parts) {
            b = ""
            for (i = 0; i < 4; i++) {
                w = substr(a, i * 8 + 1, 8)
                b = b substr(w, 7, 2) substr(w, 5, 2) substr(w, 3, 2) substr(w, 1, 2)
            }
            b = tolower(b)
            if (b == "00000000000000000000000000000000") return "::"
            if (b == "00000000000000000000000000000001") return "::1"
            if (substr(b, 1, 24) == "00000000000000000000ffff") return "::ffff:" word_bytes(substr(a, 25, 8))
            out = ""
            for (i = 0; i < 8; i++) {
                g = substr(b, i * 4 + 1, 4)
                sub(/^0+/, "", g)
                out = out (i ? ":" : "") (g == "" ? "0" : g)
            }
            return out
        }
        FNR == 1 { next }
        $4 != "0A" { next }
        {
            split($2, local_addr, ":")
            port = hex(local_addr[2])
            if (length(local_addr[1]) == 8) host = word_bytes(local_addr[1])
            else host = "[" v6(local_addr[1]) "]"
            print "LISTEN 0 0 " host ":" port " *:*"
        }
    ' "${tables[@]}" 2>/dev/null
}

# Portable listening socket check: returns matching lines for a port
get_listen_line() {
    local port="$1"
    local socket_output=""
    local attempted=false

    if command_exists ss; then
        attempted=true
        if socket_output=$(ss -tlnp 2>/dev/null); then
            printf '%s\n' "$socket_output" | grep -E "[:\.]${port}([[:space:]]|$)" || true
            return 0
        fi
    fi

    if command_exists netstat; then
        attempted=true
        if [[ "$OS_TYPE" == "macos" ]]; then
            if socket_output=$(netstat -an -ptcp 2>/dev/null); then
                printf '%s\n' "$socket_output" | grep LISTEN | grep -E "[:\.]${port}([[:space:]]|$)" || true
                return 0
            fi
        else
            if socket_output=$(netstat -tlnp 2>/dev/null); then
                printf '%s\n' "$socket_output" | grep -E "[:\.]${port}([[:space:]]|$)" || true
                return 0
            fi
        fi
    fi

    if [[ "$attempted" == "true" ]]; then
        return 2
    fi
    if socket_output=$(proc_net_listen_lines); then
        printf '%s\n' "$socket_output" | grep -E "[:\.]${port}([[:space:]]|$)" || true
        return 0
    fi
    return 1
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

is_numeric_ip_host() {
    local host="$1"
    if command_exists python3; then
        python3 -I -B -S -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$host" 2>/dev/null
    else
        if [[ "$host" == *:* ]]; then
            [[ "$host" =~ ^[0-9A-Fa-f:.]+$ ]]
            return
        fi
        [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
        local octet
        local -a octets=()
        IFS=. read -r -a octets <<< "$host"
        for octet in "${octets[@]}"; do
            [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
            [[ "$((10#$octet))" -le 255 ]] || return 1
        done
        return 0
    fi
}

AI_SERVICE_PORTS="11434:Ollama
8080:LM Studio / text-gen-webui
5000:text-gen-webui (alt)
7860:Gradio / Stable Diffusion WebUI
8188:ComfyUI
3000:Open WebUI
3001:AnythingLLM
1234:LM Studio (alt)
8000:vLLM / FastChat
5001:LocalAI
30000:SGLang
4000:LiteLLM proxy
4096:OpenCode Server
18789:OpenClaw Gateway
50052:llama.cpp RPC server
9090:Prometheus (AI metrics)"

# Print the first common AI service port listening beyond loopback.
# Returns 0 when one is exposed, 1 when none is, 2 when listeners can't be read.
ai_service_exposure() {
    local entry port name listen_line host
    while IFS= read -r entry; do
        port="${entry%%:*}"
        name="${entry#*:}"
        listen_line=$(get_listen_line "$port") || return 2
        [[ -n "$listen_line" ]] || continue
        if ! is_bound_loopback_only "$listen_line" "$port"; then
            if is_bound_all_interfaces "$listen_line" "$port"; then
                host="all interfaces"
            else
                host=$(get_non_loopback_listen_host "$listen_line" "$port" || echo "a network interface")
            fi
            printf 'port %s (commonly %s) listens on %s\n' "$port" "$name" "$host"
            return 0
        fi
    done <<< "$AI_SERVICE_PORTS"
    return 1
}

# ─── Checks ─────────────────────────────────────────────────────────────────────

check_network_exposure() {
    section "01" "Network Exposure"

    local ai_ports="$AI_SERVICE_PORTS"

    local found_any=false
    local listener_query_failed=false
    local listener_query_unavailable=false
    local listen_rc=0

    while IFS= read -r entry; do
        local port="${entry%%:*}"
        local name="${entry#*:}"

        local listen_line=""
        if listen_line=$(get_listen_line "$port"); then
            :
        else
            listen_rc=$?
            if [[ "$listen_rc" -eq 2 ]]; then
                listener_query_failed=true
            else
                listener_query_unavailable=true
            fi
            continue
        fi

        if [[ -n "$listen_line" ]]; then
            found_any=true
            if is_bound_all_interfaces "$listen_line" "$port"; then
                EXPOSED_CRITICAL_PORTS+=("$port")
                result_cooked "Unidentified service on port ${port} (commonly ${name}) is listening on ALL interfaces" "Bind ${name} to 127.0.0.1 or restrict port ${port} with a firewall"
            elif is_bound_loopback_only "$listen_line" "$port"; then
                result_safe "Unidentified service on port ${port} (commonly ${name}) is bound to localhost only"
            else
                local bind_host
                bind_host=$(get_non_loopback_listen_host "$listen_line" "$port" || echo "non-loopback interface")
                result_warming "Unidentified service on port ${port} (commonly ${name}) is bound to non-loopback interface ${bind_host}" "Verify port ${port} requires network access; bind to 127.0.0.1 if local-only"
            fi
        fi
    done <<< "$ai_ports"

    if [[ "$listener_query_failed" == "true" ]]; then
        result_unknown "Network listener inspection failed — exposure status UNKNOWN" "Run ss -tlnp (Linux) or netstat -an -ptcp (macOS); see https://iscooked.com/unknowns#network"
    elif [[ "$listener_query_unavailable" == "true" ]]; then
        result_skip "Network listener inspection requires ss or netstat"
    elif [[ "$found_any" == "false" ]]; then
        result_safe "No common AI service ports detected as listening"
    fi
}

# Parse bounded model metadata without printing model names or other response data.
api_model_metadata() {
    python3 -I -B -S -c '
import json, sys
kind = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    if not isinstance(obj, dict): raise ValueError()
    if kind == "Ollama":
        models = obj.get("models")
        if isinstance(models, list) and all(isinstance(m, dict) and isinstance(m.get("name"), str) for m in models): print("Ollama")
    else:
        models = obj.get("data")
        if obj.get("object") == "list" and isinstance(models, list) and all(isinstance(m, dict) and isinstance(m.get("id"), str) for m in models):
            owners = {m.get("owned_by") for m in models if isinstance(m.get("owned_by"), str)}
            print("LM Studio" if owners == {"lmstudio"} else "vLLM" if owners == {"vllm"} else "models")
except (ValueError, TypeError, RecursionError): pass
' "$1" 2>/dev/null
}

check_api_auth() {
    section "02" "API Authentication"
    if ! command_exists curl || ! command_exists python3; then
        result_skip "curl and python3 are required for bounded API authentication checks"
        return
    fi

    # Scope: Ollama /api/tags and OpenAI-compatible /v1/models in LM Studio
    # and vLLM. Version-independent shape checks fail closed on changed schemas.
    # No inference, credentials, URL discovery, or redirects. Only literal local
    # socket addresses and the three conventional localhost ports are probed.
    local port expected route lines line host target url response status body
    local identity metadata exposed seen count ordered loopbacks
    local listener_inventory_reported=false
    local results_before=$TOTAL_CHECKS
    for port in 11434 1234 8000; do
        case "$port" in
            11434) expected="Ollama"; route="/api/tags" ;;
            1234) expected="LM Studio"; route="/v1/models" ;;
            8000) expected="vLLM"; route="/v1/models" ;;
        esac
        local listener_inventory_status="ok"
        local listen_rc=0
        if lines=$(get_listen_line "$port"); then
            :
        else
            listen_rc=$?
            if [[ "$listen_rc" -eq 2 ]]; then
                listener_inventory_status="error"
            else
                listener_inventory_status="unavailable"
            fi
            if [[ "$listener_inventory_reported" == "false" ]]; then
                if [[ "$listener_inventory_status" == "error" ]]; then
                    result_unknown "API bind exposure inspection failed — bind status UNKNOWN"
                else
                    result_skip "API bind exposure inspection requires ss or netstat"
                fi
                listener_inventory_reported=true
            fi
            # API checks can still probe the documented localhost endpoint when
            # listener inventory is unavailable. Curl status and metadata checks
            # below determine whether that endpoint responds.
            lines=""
        fi
        # Prefer exposed binds when wildcard and loopback resolve to one target.
        ordered=""; loopbacks=""
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            host=$(get_listen_host "$line" "$port")
            if is_loopback_host "$host"; then
                loopbacks="${loopbacks}${line}"$'\n'
            else
                ordered="${ordered}${line}"$'\n'
            fi
        done <<< "$lines"
        lines="${ordered}${loopbacks}"
        [[ -n "$lines" ]] || lines="fallback"
        seen="|"; count=0
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            identity=""; exposed=false
            if [[ "$line" == "fallback" ]]; then
                host="127.0.0.1"
            else
                host=$(get_listen_host "$line" "$port")
                # Refuse hostnames and malformed socket data before building URLs.
                if [[ "$host" != "*" ]] && ! python3 -I -B -S -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$host" 2>/dev/null; then
                    result_skip "API port ${port}: unsupported local bind address"
                    continue
                fi
                is_loopback_host "$host" || exposed=true
                case "$line" in
                    *'"ollama"'*|*'/ollama '*) identity="Ollama" ;;
                    *'"llmster"'*|*'"lm-studio"'*|*'"LM Studio"'*) identity="LM Studio" ;;
                    *'"vllm"'*|*'/vllm '*) identity="vLLM" ;;
                esac
            fi
            target="$host"
            case "$host" in
                '0.0.0.0'|'*') target="127.0.0.1" ;;
                '::') target="::1" ;;
            esac
            # Deduplicate the same bind/endpoint and bound work even with many sockets.
            [[ "$seen" != *"|${target}|"* ]] || continue
            seen="${seen}${target}|"
            count=$((count + 1))
            if [[ "$count" -gt 8 ]]; then
                result_skip "API port ${port}: additional bind addresses beyond probe limit"
                break
            fi
            url="http://$(format_http_host "$target"):${port}${route}"
            response=$(curl -q -s --connect-timeout 2 --max-time 5 --max-filesize 65536 --noproxy '*' --proto '=http' -w '\n%{http_code}' "$url" 2>/dev/null) || response=$'\n000'
            status="${response##*$'\n'}"
            body="${response%$'\n'*}"
            metadata=""
            if [[ "$status" == "200" && "${#body}" -le 65536 ]]; then
                metadata=$(printf '%s' "$body" | api_model_metadata "$expected")
                if [[ "$metadata" == "$expected" ]]; then identity="$expected"; fi
            fi
            if [[ "$identity" != "$expected" ]]; then
                if [[ "$status" != "000" ]]; then
                    result_skip "API port ${port}${route}: service identity unconfirmed; HTTP ${status} does not establish AI API access"
                fi
                continue
            fi
            case "$status" in
                200)
                    if [[ -z "$metadata" ]]; then
                        result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (unexpected model-list response)" "Verify service on port ${port}; see https://iscooked.com/unknowns#network"
                    elif [[ "$listener_inventory_status" != "ok" ]]; then
                        result_unknown "${identity} ${route} on port ${port} responds without authentication; bind exposure is UNKNOWN" "Check bind address with ss -tlnp; see https://iscooked.com/unknowns#network"
                    elif [[ "$exposed" == "true" ]]; then
                        local api_hint="Require authentication or bind ${identity} to 127.0.0.1"
                        if [[ "$FULL_SCAN" == "true" ]] && is_exposed_critical_port "$port"; then
                            record_result critical "${identity} ${route} on port ${port} accessible without authentication on a non-loopback interface; correlated with Check 01 (+4 pts)" "$api_hint" 4
                        else
                            result_cooked "${identity} ${route} on port ${port} accessible without authentication on a non-loopback interface; correlate with network exposure (same endpoint)" "$api_hint"
                        fi
                    else
                        result_warming "${identity} ${route} on port ${port} accessible without authentication on localhost; other routes were not tested" "Put ${identity} behind an authenticated proxy or keep it bound strictly to localhost"
                    fi ;;
                401) result_safe "${identity} ${route} on port ${port} requires authentication (HTTP 401); other routes were not tested" ;;
                403) result_safe "${identity} ${route} on port ${port} denied access (HTTP 403); other routes were not tested" ;;
                3??) result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (HTTP ${status} redirect, not followed)" "Check redirect target on port ${port}; see https://iscooked.com/unknowns#network" ;;
                *) result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (HTTP ${status}; unreachable, failed, or unsupported endpoint)" "Inspect ${identity} status on port ${port}; see https://iscooked.com/unknowns#network" ;;
            esac
        done <<< "$lines"
    done

    if [[ "$TOTAL_CHECKS" -eq "$results_before" ]]; then
        result_skip "No Ollama, LM Studio, or vLLM API is running on its default port; nothing to test"
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
            # Check if world-readable. Consume the whole find stream via wc -l
            # (bounded: a single count) so find never hits SIGPIPE — the old
            # `| head -5` closed the pipe early, killing find under pipefail and
            # misreporting large dirs as "inspection incomplete". A genuine find
            # failure (non-zero exit, e.g. permission error) still reports skip.
            local wr_count
            if wr_count=$(find "$dir" -type f -perm -o+r 2>/dev/null | wc -l); then
                if [[ "$wr_count" -gt 0 ]]; then
                    result_warming "Model directory ${dir} is world-readable (${wr_count} files)" "Restrict file access: chmod -R o-rwx \"${dir}\""
                elif [[ ! -r "$dir" || ! -x "$dir" ]]; then
                    result_skip "Model directory ${dir} is not readable — inspection incomplete, permissions unknown"
                else
                    result_safe "No world-readable file modes found in ${dir}; write access is assessed separately"
                fi
            else
                result_skip "Model directory ${dir} — inspection incomplete, permissions unknown"
            fi

            # Check if world-writable
            local world_writable_count
            if ! world_writable_count=$(find "$dir" -maxdepth 2 -perm -o+w 2>/dev/null | wc -l); then
                result_unknown "Model directory ${dir} world-write inspection incomplete" "Inspect directory permissions with ls -ld \"${dir}\"; see https://iscooked.com/unknowns#files"
            elif [[ "$world_writable_count" -gt 0 ]]; then
                result_cooked "Files in ${dir} are world-writable!" "Remove world-write access: chmod -R o-w \"${dir}\""
            fi
        fi
    done <<< "$model_dirs_list"

    if [[ "$found_models" == "false" ]]; then
        result_skip "No common model directories found"
    fi
}

# Metadata only: no exec, socket requests, container writes, or environment reads.
docker_read_metadata() {
    if command_exists timeout; then
        timeout 5 docker "$@"
    elif command_exists gtimeout; then
        gtimeout 5 docker "$@"
    elif command_exists python3; then
        python3 -I -B -S -c 'import subprocess, sys
try:
    sys.exit(subprocess.run(["docker", *sys.argv[1:]], timeout=5).returncode)
except (OSError, subprocess.TimeoutExpired):
    sys.exit(1)' "$@"
    else
        return 1
    fi
}

check_docker_risks() {
    section "04" "Docker / Container Risks"

    if ! command_exists docker; then
        result_skip "Docker not installed, skipping container checks"
        return
    fi

    # Do not confuse a failed daemon/list operation with an empty inventory.
    local security_options daemon_endpoint="${DOCKER_HOST:-}" daemon_mode=unknown
    if ! security_options=$(docker_read_metadata info --format '{{json .SecurityOptions}}' 2>&1); then
        if printf '%s' "$security_options" | grep -qiE 'cannot connect to the docker daemon|is the docker daemon running|no such file or directory|connection refused' \
            && ! printf '%s' "$security_options" | grep -qi 'permission denied'; then
            result_skip "Docker daemon is not running"
        else
            result_unknown "Docker daemon inspection incomplete — UNKNOWN (unreachable or bounded command unavailable)" "Run docker info --format '{{json .SecurityOptions}}'; see https://iscooked.com/unknowns#docker"
        fi
        return
    fi

    # Associate daemon security options only with its exact Unix endpoint.
    # A remote/context daemon says nothing about an unrelated mounted socket.
    if [[ -n "${DOCKER_CONTEXT:-}" || -z "$daemon_endpoint" ]]; then
        daemon_endpoint=$(docker_read_metadata context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
    fi
    # Only a parsed array of strings can establish daemon security mode.
    # Without a JSON parser, retain unknown rather than infer rootful access.
    if command_exists python3; then
        daemon_mode=$(printf '%s' "$security_options" | python3 -I -B -S -c 'import json, sys
try:
    options = json.load(sys.stdin)
    if not isinstance(options, list) or not all(isinstance(x, str) for x in options):
        raise ValueError("invalid security options")
    names = {x.split(",", 1)[0] for x in options}
    print("rootless" if "name=rootless" in names else "unknown" if "name=userns" in names else "rootful")
except (ValueError, TypeError):
    print("unknown")' 2>/dev/null) || daemon_mode=unknown
    fi

    local ai_containers inventory
    if ! inventory=$(docker_read_metadata ps --format '{{.Names}} {{.Image}}' 2>/dev/null); then
        result_unknown "Docker container inventory UNKNOWN (inspection incomplete)"
        return
    fi
    ai_containers=$(printf '%s\n' "$inventory" | grep -iE 'ollama|llama|text-gen|webui|comfy|vllm|localai|stable|diffusion|lmstudio|open-webui|litellm' || true)

    if [[ -z "$ai_containers" ]]; then
        result_skip "No AI-related containers running"
        return
    fi

    while IFS= read -r container_line; do
        local cname
        cname=$(echo "$container_line" | awk '{print $1}')

        # Check if running as root
        local user configured_user userns_mode
        if ! user=$(docker_read_metadata inspect --format '{{.Config.User}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' user and mount status UNKNOWN (inspection incomplete)"
            continue
        fi
        configured_user=${user%%:*}
        if [[ -z "$configured_user" || "$configured_user" == "root" || "$configured_user" == "0" ]]; then
            result_cooked "Container '${cname}' is running as root" "Set a non-root USER in the container image or --user flag"
        else
            result_safe "Container '${cname}' is running as user '${user}'"
        fi

        userns_mode=$(docker_read_metadata inspect --format '{{.HostConfig.UsernsMode}}' "$cname" 2>/dev/null || echo "unknown")

        # Check privileged mode
        local privileged
        if ! privileged=$(docker_read_metadata inspect --format '{{.HostConfig.Privileged}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' privileged status UNKNOWN (inspection incomplete)" "Run docker inspect '${cname}'; see https://iscooked.com/unknowns#docker"
        fi
        if [[ "$privileged" == "true" ]]; then
            result_cooked "Container '${cname}' is running in PRIVILEGED mode" "Remove --privileged from container '${cname}' and grant only needed capabilities"
        fi

        # Check host network
        local network
        if ! network=$(docker_read_metadata inspect --format '{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' network mode UNKNOWN (inspection incomplete)" "Run docker inspect '${cname}'; see https://iscooked.com/unknowns#docker"
        fi
        if [[ "$network" == "host" ]]; then
            result_warming "Container '${cname}' is using host networking" "Use a bridge network and publish ports explicitly to 127.0.0.1"
        fi

        # Include mode and destination: RO sockets still permit daemon API calls.
        local mounts source destination rw mount_type extra mount_line
        local finding_level finding_message mount_index candidate_index sensitive_reported=false
        local -a mount_sources=() mount_levels=() mount_messages=()
        if ! mounts=$(docker_read_metadata inspect --format '{{range .Mounts}}{{.Source}}|{{.Destination}}|{{.RW}}|{{.Type}}{{"\n"}}{{end}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' mount status UNKNOWN (inspection incomplete)"
            continue
        fi
        while IFS= read -r mount_line; do
            [[ -n "$mount_line" ]] || continue
            IFS='|' read -r source destination rw mount_type extra <<< "$mount_line"
            # tmpfs has no backing host path, unlike bind and volume mounts.
            [[ "$mount_type" == tmpfs ]] && continue
            if [[ -n "$extra" || "$source" != /* || ( -n "$mount_type" && "$mount_type" != bind && "$mount_type" != volume ) ]]; then
                result_unknown "Container '${cname}' mount metadata UNKNOWN (inspection incomplete)"
                continue
            fi
            finding_level=0
            finding_message=""
            if [[ "$source" == "/" ]]; then
                case "$rw" in
                    true) finding_level=4; finding_message="Container '${cname}' mounts the host root filesystem at '${destination}' read-write; host files may be modified" ;;
                    false) finding_level=3; finding_message="Container '${cname}' mounts the host root filesystem at '${destination}' read-only; host files may be disclosed" ;;
                    *) finding_level=1; finding_message="Container '${cname}' host root filesystem mount mode UNKNOWN (inspection incomplete)" ;;
                esac
            elif [[ "$source" == */docker.sock || "$destination" == */docker.sock || "$source" == *docker*.sock || "$destination" == *docker*.sock || ( "$daemon_endpoint" == unix://* && "$source" == "${daemon_endpoint#unix://}" ) ]]; then
                local socket_note="effective daemon access could not be verified"
                if [[ "$source" == *proxy* || "$destination" == *proxy* ]]; then
                    socket_note+="; possible socket proxy, restrictions unverified"
                elif [[ "$daemon_endpoint" == "unix://${source}" && "$daemon_mode" == rootless ]]; then
                    socket_note+="; rootless daemon confirmed by security options"
                elif [[ "$source" == /run/user/*/docker.sock ]]; then
                    socket_note+="; rootless daemon path candidate"
                else
                    socket_note+="; rootful or rootless daemon status unverified"
                fi
                if [[ "$rw" == false ]]; then
                    socket_note+="; read-only mount does not restrict Docker API operations"
                fi
                if [[ "$daemon_endpoint" == "unix://${source}" && "$daemon_mode" == rootful && ( -z "$configured_user" || "$configured_user" == 0 || "$configured_user" == root ) && ( -z "$userns_mode" || "$userns_mode" == host ) && "$source" != *proxy* && "$destination" != *proxy* ]]; then
                    finding_level=4
                    finding_message="Container '${cname}' mounts a rootful Docker daemon socket '${source}' at '${destination}' as root without user namespace isolation; daemon control risk (socket mount mode does not restrict API operations)"
                else
                    finding_level=3
                    finding_message="Container '${cname}' has a Docker socket mount '${source}' at '${destination}'; ${socket_note}"
                fi
            elif [[ "$source" == /etc || "$source" == /etc/* || "$source" == /root || "$source" == /root/* || "$source" == /home/*/* || "$source" =~ ^/home/[^/]+$ ]]; then
                finding_level=2
                finding_message="Container '${cname}' has sensitive host paths mounted ('${source}')"
            fi
            [[ "$finding_level" -gt 0 ]] || continue
            # Score each source once, selecting its strongest observed access.
            # Indexed arrays avoid evaluating untrusted paths as array expressions.
            mount_index=${#mount_sources[@]}
            if [[ "${#mount_sources[@]}" -gt 0 ]]; then
                for candidate_index in "${!mount_sources[@]}"; do
                    if [[ "${mount_sources[candidate_index]}" == "$source" ]]; then
                        mount_index=$candidate_index
                        break
                    fi
                done
            fi
            if [[ "$finding_level" -gt "${mount_levels[mount_index]:-0}" ]]; then
                mount_sources[mount_index]=$source
                mount_levels[mount_index]=$finding_level
                mount_messages[mount_index]=$finding_message
            fi
        done <<< "$mounts"
        if [[ "${#mount_sources[@]}" -gt 0 ]]; then
            for mount_index in "${!mount_sources[@]}"; do
                case "${mount_levels[mount_index]}" in
                    4) result_cooked "${mount_messages[mount_index]}" "Remove host root or Docker socket mount from container '${cname}'" ;;
                    3) result_warming "${mount_messages[mount_index]}" "Avoid mounting host root or Docker sockets into AI containers" ;;
                    2)
                        if [[ "$sensitive_reported" == false ]]; then
                            result_warming "Container '${cname}' has sensitive host paths mounted" "Mount only required project/model subdirectories instead of /etc, /root, or home"
                            sensitive_reported=true
                        fi
                        ;;
                    1) result_unknown "${mount_messages[mount_index]}" "Inspect mounts with docker inspect '${cname}'; see https://iscooked.com/unknowns#docker" ;;
                esac
            done
        fi

    done <<< "$ai_containers"
}

# Browser control inspection uses process evidence, never a guessed default port.
# Only /json/version is read; response-supplied control URLs are never followed.
browser_debugging_evidence() {
    python3 -I -B -S - "$OS_TYPE" <<'PY'
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

def read_command(argv):
    try:
        # Spool outside Python memory, then read at most the inspection budget.
        # The command timeout also bounds capture time on unusually large hosts.
        with tempfile.TemporaryFile() as output:
            p = subprocess.run(argv, stdout=output, stderr=subprocess.DEVNULL,
                               timeout=4, check=False)
            if p.returncode == 0 and output.tell() <= 4194304:
                output.seek(0)
                return output.read(4194304).decode('utf-8', 'replace')
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None

processes = read_command(['ps', '-ax', '-o', 'pid=', '-o', 'args='])
if processes is None:
    print('unknown|Browser process inspection unavailable')
    sys.exit()
candidates = set()
browsers = {'chrome', 'chromium', 'chromium-browser', 'google-chrome',
            'google-chrome-stable', 'google-chrome-beta', 'google-chrome-unstable',
            'headless_shell', 'msedge', 'microsoft-edge', 'brave', 'brave-browser',
            'Google Chrome', 'Google Chrome Canary', 'Chromium', 'Microsoft Edge',
            'Brave Browser'}
parse_unknown = False
for line in processes.splitlines():
    try:
        pid, command = line.strip().split(None, 1)
    except ValueError:
        continue
    if not pid.isdecimal():
        continue
    args = []
    tail = command
    # macOS ps does not quote application executable paths containing spaces.
    if sys.argv[1] == 'macos' and command.startswith('/'):
        for name in browsers:
            marker = '.app/Contents/MacOS/' + name + ' '
            if marker in command:
                executable, tail = command.split(marker, 1)
                args = [executable + marker.rstrip()]
                break
    lexer = shlex.shlex(tail, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        for token in lexer:
            args.append(token)
    except ValueError:
        # ps renders literal apostrophes without shell quoting. Retain known
        # executable identity, but do not guess argument boundaries or probe.
        if (args and os.path.basename(args[0]) in browsers
                and re.search(r'(?:^|\s)--remote-debugging-port(?:=|\s|$)', command)):
            parse_unknown = True
        continue
    if not args or os.path.basename(args[0]) not in browsers:
        continue
    for i, arg in enumerate(args[1:], 1):
        value = None
        if arg.startswith('--remote-debugging-port='):
            value = arg.partition('=')[2]
        elif arg == '--remote-debugging-port' and i + 1 < len(args):
            value = args[i + 1]
        if value is not None and value.isascii() and value.isdecimal() and len(value) <= 5:
            if 0 <= int(value) <= 65535:
                candidates.add((pid, int(value)))
if parse_unknown:
    print('unknown|Browser debugging candidate found; process arguments could not be parsed reliably')
if not candidates:
    if not parse_unknown:
        print('skip|No known browser process with a network debugging flag found')
    sys.exit()
listeners = read_command(['ss', '-tlnp'])
kind = 'ss'
if listeners is None:
    kind = 'netstat'
    argv = ['netstat', '-an', '-ptcp'] if sys.argv[1] == 'macos' else ['netstat', '-tlnp']
    listeners = read_command(argv)
if listeners is None and sys.argv[1] == 'linux':
    # Same kernel-table fallback as proc_net_listen_lines, in ss format.
    kind = 'ss'
    rows = []
    proc_net = os.environ.get('ISCOOKED_TEST_PROC_NET', '/proc/net')
    for table in ('tcp', 'tcp6'):
        try:
            with open(os.path.join(proc_net, table)) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for row in lines:
            fields = row.split()
            if len(fields) < 4 or fields[3] != '0A':
                continue
            try:
                addr, port = fields[1].split(':')
                raw = bytes.fromhex(addr)
                # Each 32-bit word is stored in host (little-endian) byte order.
                packed = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
                ip = ipaddress.ip_address(packed)
                rows.append('LISTEN 0 0 [%s]:%d *:*' % (ip, int(port, 16)))
            except ValueError:
                continue
    if rows or os.path.exists(os.path.join(proc_net, 'tcp')):
        listeners = '\n'.join(rows)
if listeners is None:
    print('unknown|Browser debugging candidate found; listener inspection unavailable')
    sys.exit()

sockets = []
for line in listeners.splitlines():
    fields = line.split()
    if len(fields) < 5 or 'LISTEN' not in fields:
        continue
    address = fields[3]
    try:
        if kind == 'netstat' and sys.argv[1] == 'macos':
            host, port = address.rsplit('.', 1)
        else:
            host, port = address.rsplit(':', 1)
        port = int(port)
        host = host.strip('[]')
        # An unqualified ss wildcard is dual-stack/IPv6. netstat tcp is IPv4.
        if host == '*':
            host = '::' if kind == 'ss' or fields[0] == 'tcp6' else '0.0.0.0'
        ip = ipaddress.ip_address(host)
    except ValueError:
        continue
    pids = set(re.findall(r'pid=(\d+)', line))
    if kind == 'netstat':
        pids.update(re.findall(r'\b(\d+)/', line))
    sockets.append((ip, port, pids))

def metadata(ip, port):
    # Wildcards probe the corresponding loopback family. Other destinations must
    # be literal addresses obtained from the local listening-socket inventory.
    target = ipaddress.ip_address('::1' if ip.version == 6 else '127.0.0.1') if ip.is_unspecified else ip
    host = '[' + str(target) + ']' if target.version == 6 else str(target)
    url = 'http://' + host + ':' + str(port) + '/json/version'
    try:
        with tempfile.TemporaryFile() as output:
            p = subprocess.run(['curl', '-q', '--silent', '--fail', '--noproxy', '*',
                '--proxy', '', '--proto', '=http', '--max-redirs', '0',
                '--connect-timeout', '1', '--max-time', '3', '--max-filesize', '65536',
                '--url', url], stdout=output, stderr=subprocess.DEVNULL, timeout=4)
            if p.returncode != 0 or output.tell() > 65536:
                return False
            output.seek(0)
            data = json.loads(output.read(65537))
        return (isinstance(data, dict)
                and isinstance(data.get('Browser'), str)
                and re.match(r'^(?:Chrome|Chromium|HeadlessChrome|Microsoft Edge|Edg)/', data['Browser']) is not None
                and isinstance(data.get('Protocol-Version'), str)
                and re.fullmatch(r'\d+\.\d+', data['Protocol-Version']) is not None
                and isinstance(data.get('webSocketDebuggerUrl'), str)
                and re.match(r'^wss?://[^/]+/devtools/browser/[^\s]+$', data['webSocketDebuggerUrl']) is not None)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False

seen = set()
probes = 0
for pid, port in sorted(candidates):
    matching = [(ip, p) for ip, p, pids in sockets
                if (p == port or (port == 0 and pid in pids)) and (not pids or pid in pids)]
    if not matching:
        print('unknown|Browser debugging candidate PID ' + pid + '; listener exposure could not be verified')
    for ip, p in matching:
        if (ip, p) in seen:
            continue
        seen.add((ip, p))
        if probes >= 32:
            print('unknown|Browser debugging inspection limit reached')
            sys.exit()
        probes += 1
        if not metadata(ip, p):
            print('unknown|Browser debugging candidate; metadata inspection did not verify browser control')
        elif ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback):
            print('safe|Verified browser debugging endpoint is bound to loopback only')
        else:
            print('cooked|Verified browser remote-debugging endpoint listens on a non-loopback interface; public reachability is not established')
PY
}

check_browser_debugging() {
    section "13" "Browser Remote Debugging"
    if ! command_exists python3 || ! command_exists curl; then
        result_skip "Browser debugging inspection requires optional python3 and curl"
        return
    fi
    local evidence status message
    if ! evidence=$(browser_debugging_evidence 2>/dev/null); then
        result_unknown "Browser debugging inspection failed"
        return
    fi
    while IFS='|' read -r status message; do
        case "$status" in
            cooked) result_cooked "$message" "Bind browser debugging to 127.0.0.1 or use --remote-debugging-pipe" ;;
            safe) result_safe "$message" ;;
            unknown) result_unknown "$message" "Inspect browser flags and listeners; see https://iscooked.com/unknowns#network" ;;
            skip) result_skip "$message" ;;
        esac
    done <<< "$evidence"
}

check_gpu_exposure() {
    section "05" "GPU Driver Exposure"

    local found_gpu=false

    # NVIDIA (Linux)
    if command_exists nvidia-smi; then
        found_gpu=true
        # Check if nvidia management services have exposed ports
        local nvidia_listen="" nvidia_listener_state="unavailable" nvidia_socket_output=""
        # More targeted check: look for nvidia-related listeners
        if command_exists ss; then
            nvidia_listener_state="error"
            if nvidia_socket_output=$(ss -tlnp 2>/dev/null); then
                nvidia_listener_state="ok"
                nvidia_listen=$(printf '%s\n' "$nvidia_socket_output" | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
            fi
        elif command_exists netstat; then
            nvidia_listener_state="error"
            if [[ "$OS_TYPE" == "macos" ]]; then
                if nvidia_socket_output=$(netstat -an -ptcp 2>/dev/null); then
                    nvidia_listener_state="ok"
                    nvidia_listen=$(printf '%s\n' "$nvidia_socket_output" | grep LISTEN | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
                fi
            else
                if nvidia_socket_output=$(netstat -tlnp 2>/dev/null); then
                    nvidia_listener_state="ok"
                    nvidia_listen=$(printf '%s\n' "$nvidia_socket_output" | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" || true)
                fi
            fi
        fi

        if [[ "$nvidia_listener_state" == "error" ]]; then
            result_unknown "NVIDIA listener inspection failed — management port status UNKNOWN" "Run ss -tlnp; see https://iscooked.com/unknowns#network"
        elif [[ "$nvidia_listener_state" == "unavailable" ]]; then
            result_skip "NVIDIA listener inspection requires ss or netstat"
        elif [[ -n "$nvidia_listen" ]]; then
            result_warming "NVIDIA management service has network-exposed ports" "Bind NVIDIA management listeners to localhost or restrict with a firewall"
        else
            result_safe "NVIDIA GPU detected, no management ports exposed"
        fi

        # Check nvidia device permissions (Linux only)
        if [[ "$OS_TYPE" == "linux" && -e /dev/nvidia0 ]]; then
            local nv_perms
            if ! nv_perms=$(get_file_perms /dev/nvidia0); then
                result_unknown "/dev/nvidia0 permission inspection failed" "Run ls -ld /dev/nvidia0; see https://iscooked.com/unknowns#files"
            elif [[ ! "$nv_perms" =~ ^[0-7]+$ ]]; then
                result_unknown "/dev/nvidia0 returned an invalid permission value" "Run ls -ld /dev/nvidia0; see https://iscooked.com/unknowns#files"
            elif [[ "${nv_perms: -1}" -ge 6 ]]; then
                result_warming "/dev/nvidia0 is accessible to all users (mode ${nv_perms})" "Restrict /dev/nvidia0 to the video/render group (chmod 660)"
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
            if ! render_perms=$(get_file_perms /dev/dri/renderD128); then
                result_unknown "/dev/dri/renderD128 permission inspection failed" "Run ls -ld /dev/dri/renderD128; see https://iscooked.com/unknowns#files"
            elif [[ ! "$render_perms" =~ ^[0-7]+$ ]]; then
                result_unknown "/dev/dri/renderD128 returned an invalid permission value" "Run ls -ld /dev/dri/renderD128; see https://iscooked.com/unknowns#files"
            elif [[ "${render_perms: -1}" -ge 6 ]]; then
                result_warming "/dev/dri/renderD128 is world-accessible (mode ${render_perms})" "Restrict /dev/dri/renderD128 to the render group (chmod 660)"
            fi
        fi
    fi

    # macOS GPU — Metal is sandboxed, but check for external GPU access
    if [[ "$OS_TYPE" == "macos" ]]; then
        if system_profiler SPDisplaysDataType 2>/dev/null | grep -qi "Metal\|GPU"; then
            found_gpu=true
            result_skip "macOS GPU capability detected; runtime access policy was not inspected"
        fi
    fi

    if [[ "$found_gpu" == "false" ]]; then
        result_skip "No GPU devices detected"
    fi
}

check_mcp_config() {
    section "14" "MCP Configuration"
    if ! command -v python3 >/dev/null 2>&1; then
        result_skip "MCP configuration inspection requires optional python3"
        return
    fi
    local mcp_output mcp_severity mcp_message mcp_hint
    if ! mcp_output=$(python3 -I -B -S - 2>/dev/null <<'MCP_PY'
import errno
import ipaddress
import json
import os
import re
import stat
import sys
import urllib.parse
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

LIMIT = 1048576
home = Path.home()
cwd = Path.cwd()

# Tuple: (path, label, schema_kind, project_local, strict_mcp_file)
paths = [
    (home / '.config/Claude/claude_desktop_config.json', 'Claude Desktop Linux', 'mcpServers', False, False),
    (home / 'Library/Application Support/Claude/claude_desktop_config.json', 'Claude Desktop macOS', 'mcpServers', False, False),
    (cwd / '.mcp.json', 'Claude Code project', 'mcpServers', True, True),
    (home / '.claude.json', 'Claude Code user', 'claude_user', False, False),
    (home / '.cursor/mcp.json', 'Cursor user', 'mcpServers', False, True),
    (cwd / '.cursor/mcp.json', 'Cursor project', 'mcpServers', True, True),
    (home / '.config/opencode/opencode.json', 'OpenCode user', 'opencode_mcp', False, False),
    (cwd / 'opencode.json', 'OpenCode project', 'opencode_mcp', True, False),
    (home / '.codeium/windsurf/mcp_config.json', 'Windsurf user', 'mcpServers', False, True),
    (home / '.config/zed/settings.json', 'Zed user', 'zed_context_servers', False, False),
    (cwd / '.vscode/mcp.json', 'VS Code project', 'vscode_servers', True, True),
    (home / '.config/Code/User/mcp.json', 'VS Code user (Linux)', 'vscode_servers', False, True),
    (home / 'Library/Application Support/Code/User/mcp.json', 'VS Code user (macOS)', 'vscode_servers', False, True),
    (home / '.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json', 'Cline (Linux)', 'mcpServers', False, True),
    (home / 'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json', 'Cline (macOS)', 'mcpServers', False, True),
    (home / '.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json', 'Roo Code (Linux)', 'mcpServers', False, True),
    (home / 'Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json', 'Roo Code (macOS)', 'mcpServers', False, True),
    (home / '.codex/config.toml', 'Codex CLI', 'codex_toml', False, False),
    (home / '.gemini/settings.json', 'Gemini CLI', 'mcpServers', False, False),
    (home / '.gemini/antigravity/mcp_config.json', 'Antigravity', 'mcpServers', False, True),
]

COMMENT_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/')
COMMA_RE = re.compile(r'"(?:\\.|[^"\\])*"|(,)(\s*[}\]])')


def parse_jsonc(raw_bytes):
    text = raw_bytes.decode('utf-8-sig')
    stripped = COMMENT_RE.sub(lambda m: m.group(0) if m.group(0).startswith('"') else ' ', text)
    cleaned = COMMA_RE.sub(lambda m: m.group(2) if m.group(1) else m.group(0), stripped)
    return json.loads(cleaned)


def _strip_toml_comment(line):
    in_dq = False
    in_sq = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if in_dq:
            if ch == '\\':
                escaped = True
            elif ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == '#':
                return line[:idx]
    return line


def _split_toml_items(body):
    items = []
    buf = []
    depth = 0
    in_dq = False
    in_sq = False
    escaped = False
    for ch in body:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if in_dq:
            buf.append(ch)
            if ch == '\\':
                escaped = True
            elif ch == '"':
                in_dq = False
            continue
        if in_sq:
            buf.append(ch)
            if ch == "'":
                in_sq = False
            continue
        if ch == '"':
            in_dq = True
        elif ch == "'":
            in_sq = True
        elif ch in '[{':
            depth += 1
        elif ch in ']}':
            depth -= 1
        elif ch == ',' and depth == 0:
            item = ''.join(buf).strip()
            if item:
                items.append(item)
            buf = []
            continue
        buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _parse_toml_val(val):
    val = val.strip()
    if not val:
        raise ValueError()
    if val == 'true':
        return True
    if val == 'false':
        return False
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        return json.loads(val)
    if val.startswith("'") and val.endswith("'") and len(val) >= 2:
        return val[1:-1]
    if val.startswith('[') and val.endswith(']'):
        return [_parse_toml_val(item) for item in _split_toml_items(val[1:-1])]
    if val.startswith('{') and val.endswith('}'):
        out = {}
        for item in _split_toml_items(val[1:-1]):
            k, sep, v = item.partition('=')
            if not sep:
                raise ValueError()
            out[k.strip().strip('"\'')] = _parse_toml_val(v)
        return out
    if re.fullmatch(r'[+-]?\d+', val):
        return int(val)
    return val


def parse_toml(raw_bytes):
    text = raw_bytes.decode('utf-8-sig')
    if tomllib is not None:
        return tomllib.loads(text)
    root = {}
    cursor = root
    for raw_line in text.splitlines():
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            header = line[1:-1].strip()
            if not header or header.startswith('['):
                raise ValueError()
            parts = [p.strip().strip('"\'') for p in header.split('.')]
            cursor = root
            for part in parts:
                if part not in cursor or not isinstance(cursor[part], dict):
                    cursor[part] = {}
                cursor = cursor[part]
        elif '=' in line:
            k, _, v = line.partition('=')
            cursor[k.strip().strip('"\'')] = _parse_toml_val(v)
        else:
            raise ValueError()
    return root


def emit(level, message, hint=''):
    print(level + '\t' + message + '\t' + hint)


def traversable(parents, gid=None):
    # Model a non-owner account in this group, or an unrelated local account.
    return all(s.st_mode & (stat.S_IXGRP if gid == s.st_gid else stat.S_IXOTH)
               for s in parents)


def permissions(path, label, credentials):
    emitted = False
    try:
        resolved = path.resolve(strict=True)
        s = resolved.stat()
        parents = [p.stat() for p in resolved.parents]
        xattr_paths = [resolved, *resolved.parents]
        if path.is_symlink():
            link_parent = path.parent.resolve(strict=True)
            if link_parent not in xattr_paths:
                xattr_paths.extend([link_parent, *link_parent.parents])
        has_acl = False
        if hasattr(os, 'listxattr'):
            for p in xattr_paths:
                try:
                    attrs = os.listxattr(p)
                except OSError as exc:
                    if exc.errno in (getattr(errno, 'ENOTSUP', 95), getattr(errno, 'EOPNOTSUPP', 95)):
                        continue
                    raise
                if any('acl' in name.lower() for name in attrs):
                    has_acl = True
                    break
        if has_acl:
            emit('unknown', label + ': ACL permissions need manual permissions review',
                 'Inspect ACLs with getfacl or ls -le; see https://iscooked.com/unknowns#files')
            return True

        def dir_replace_risk(dir_paths):
            dir_stats = [p.stat() for p in dir_paths]
            rw_world = any(d.st_mode & stat.S_IWOTH and not d.st_mode & stat.S_ISVTX
                           and traversable(dir_stats[i:])
                           for i, d in enumerate(dir_stats))
            rw_group = any(d.st_mode & stat.S_IWGRP and not d.st_mode & stat.S_ISVTX
                           and traversable(dir_stats[i:], d.st_gid)
                           for i, d in enumerate(dir_stats))
            return rw_world, rw_group

        world = traversable(parents)
        group = traversable(parents, s.st_gid)
        replace_world, replace_group = dir_replace_risk(resolved.parents)
        if path.is_symlink():
            lp = path.parent.resolve(strict=True)
            lp_world, lp_group = dir_replace_risk([lp, *lp.parents])
            replace_world |= lp_world
            replace_group |= lp_group

        if (world and s.st_mode & stat.S_IWOTH) or replace_world:
            emit('cooked', label + ': launch configuration is world-writable or replaceable; restrict file and parent directory permissions',
                 f'Run chmod 600 "{resolved}" and ensure parent directories are not world-writable')
            emitted = True
        elif (group and s.st_mode & stat.S_IWGRP) or replace_group:
            emit('warming', label + ': launch configuration is group-writable or replaceable; restrict access to trusted administrators',
                 f'Run chmod 600 "{resolved}" and tighten parent directory group permissions')
            emitted = True
        if credentials:
            if world and s.st_mode & stat.S_IROTH:
                emit('cooked', label + ': credential-bearing configuration is readable by other local users; use mode 600 and a private parent directory',
                     f'Run chmod 600 "{resolved}" and move secrets to environment variables')
                emitted = True
            elif group and s.st_mode & stat.S_IRGRP:
                emit('warming', label + ': credential-bearing configuration is group-readable; restrict access to the intended account',
                     f'Run chmod 600 "{resolved}"')
                emitted = True
    except OSError:
        emit('unknown', label + ': effective permissions could not be inspected',
             f'Check permissions with ls -ld "{path}"; see https://iscooked.com/unknowns#files')
        emitted = True
    return emitted


def has_credentials(server):
    # Detect key names only, and never echo either names or values.
    for field in ('env', 'environment', 'headers', 'http_headers'):
        values = server.get(field, {})
        if isinstance(values, dict):
            for key, value in values.items():
                if re.search(r'key|token|secret|password|credential|authorization', str(key), re.I) and value:
                    if isinstance(value, str):
                        v = value.strip()
                        if ((v.startswith('${') and v.endswith('}'))
                                or (v.startswith('{env:') and v.endswith('}'))
                                or re.fullmatch(r'\$[A-Za-z_][A-Za-z0-9_]*', v)):
                            continue
                    return True
    return False


def is_loopback_url_host(host):
    if not host:
        return False
    h = host.strip('[]').lower()
    if h == 'localhost':
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def find_unpinned_npx_package(args):
    if '-y' not in args and '--yes' not in args:
        return None
    skip_next = False
    for idx, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in ('-p', '--package'):
            if idx + 1 < len(args):
                return args[idx + 1]
            return None
        if arg.startswith('--package='):
            return arg.partition('=')[2]
        if arg.startswith('-'):
            continue
        return arg
    return None


def is_pinned_npm_package(pkg):
    if not pkg or pkg.startswith(('/', './', '../')):
        return True
    if pkg.startswith('@'):
        if '/' not in pkg:
            return False
        _, _, rest = pkg.partition('/')
        if '@' not in rest:
            return False
        version = rest.rsplit('@', 1)[1]
    else:
        if '@' not in pkg:
            return False
        version = pkg.rsplit('@', 1)[1]
    return bool(version) and version.lower() not in ('latest', 'next', 'canary', '*')


def is_project_scoped_grant(grant):
    if grant in ('.', './'):
        return True
    if grant.startswith('./'):
        rel = grant[2:]
        return '..' not in Path(rel).parts
    if grant == '${workspaceFolder}':
        return True
    if grant.startswith('${workspaceFolder}/'):
        rel = grant[len('${workspaceFolder}/'):]
        return '..' not in Path(rel).parts
    return False


def inspect_server(server, label):
    emitted = False
    if not isinstance(server, dict):
        emit('unknown', label + ': unsupported server entry',
             'Review MCP server definition; see https://iscooked.com/unknowns#configuration')
        return True

    for url_key in ('url', 'serverUrl', 'httpUrl'):
        url_val = server.get(url_key)
        if isinstance(url_val, str) and url_val.strip().lower().startswith('http://'):
            parsed = urllib.parse.urlsplit(url_val.strip())
            if not is_loopback_url_host(parsed.hostname or ''):
                emit('cooked', label + ': remote MCP server uses unencrypted plain http:// URL',
                     'Switch remote MCP endpoint URL to https://')
                emitted = True
                break

    raw_command = server.get('command', '')
    args = server.get('args', [])
    if isinstance(raw_command, list):
        if not raw_command or not all(isinstance(x, str) for x in raw_command):
            emit('unknown', label + ': unsupported command or arguments',
                 'Check MCP server command array; see https://iscooked.com/unknowns#configuration')
            return True
        command = raw_command[0]
        extra_args = args if isinstance(args, list) and all(isinstance(a, str) for a in args) else []
        args = [*raw_command[1:], *extra_args]
    elif isinstance(raw_command, dict):
        cmd_path = raw_command.get('path', '')
        cmd_args = raw_command.get('args', [])
        if not isinstance(cmd_path, str) or not isinstance(cmd_args, list) or not all(isinstance(a, str) for a in cmd_args):
            emit('unknown', label + ': unsupported command or arguments',
                 'Check Zed context_servers command structure; see https://iscooked.com/unknowns#configuration')
            return True
        command = cmd_path
        args = cmd_args
    elif isinstance(raw_command, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        command = raw_command
    else:
        emit('unknown', label + ': unsupported command or arguments',
             'Review MCP command and args types; see https://iscooked.com/unknowns#configuration')
        return True

    executable = os.path.basename(command)
    if executable == 'npx':
        pkg = find_unpinned_npx_package(args)
        if pkg and not is_pinned_npm_package(pkg):
            emit('warming', label + ": uses unpinned 'npx -y' without an explicit @version",
                 'Pin a specific version (for example @scope/package@1.2.3) instead of unpinned npx -y')
            emitted = True

    filesystem = executable == 'mcp-server-filesystem'
    grants = args if filesystem else []
    if executable in ('npx', 'bunx'):
        for i, arg in enumerate(args):
            if re.fullmatch(r'@modelcontextprotocol/server-filesystem(?:@[^/\s]+)?', arg):
                filesystem = True
                grants = args[i + 1:]
                break
    if filesystem:
        broad = False
        complete = True
        if not grants:
            emit('unknown', label + ': filesystem server has no explicit grants; review effective access',
                 'Specify an explicit project directory grant; see https://iscooked.com/unknowns#configuration')
            emitted = True
            complete = False
        for grant in dict.fromkeys(grants):
            if grant.startswith('-'):
                continue
            if is_project_scoped_grant(grant):
                continue
            if '$' in grant or '{' in grant:
                complete = False
                emit('unknown', label + ': filesystem grant uses unresolved variables; review resolved access',
                     'Replace unresolved variables with an explicit directory or ${workspaceFolder}; see https://iscooked.com/unknowns#configuration')
                emitted = True
                continue
            expanded = Path(os.path.expanduser(grant))
            if not expanded.is_absolute():
                complete = False
                emit('unknown', label + ': relative filesystem grant depends on server working directory',
                     'Use an explicit path or ./ within the workspace; see https://iscooked.com/unknowns#configuration')
                emitted = True
                continue
            try:
                expanded = expanded.resolve()
            except (OSError, RuntimeError):
                complete = False
                emit('unknown', label + ': filesystem grant could not be resolved',
                     'Verify granted directory path exists; see https://iscooked.com/unknowns#configuration')
                emitted = True
                continue
            if expanded == Path('/') or expanded == home or expanded in home.parents:
                scope = 'entire home directory' if expanded == home else 'filesystem root or ancestor of home'
                emit('warming', label + ': filesystem server grants access to ' + scope + '; narrow grants to required project directories',
                     'Narrow filesystem server grant to a specific project subdirectory')
                emitted = True
                broad = True
            elif any(expanded == sensitive or sensitive in expanded.parents
                     for sensitive in (home / '.ssh', home / '.aws', home / '.gnupg', home / '.config', Path('/etc'))):
                emit('warming', label + ': filesystem server grants a sensitive directory; narrow grants to required project directories',
                     'Remove sensitive directory (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, /etc) from filesystem grants')
                emitted = True
                broad = True
        if not broad and complete:
            emit('safe', label + ': no broad filesystem grants identified in literal arguments')
            emitted = True
    if executable == 'mcp-server-shell' or (executable in ('npx', 'bunx') and 'mcp-server-shell' in args):
        emit('warming', label + ': known shell server configured; review command restrictions and run with minimal privileges',
             'Ensure mcp-server-shell uses a command allowlist and minimal privileges')
        emitted = True
    return emitted


found = False
seen = set()
for path, label, schema_kind, project_local, strict_mcp_file in paths:
    norm_key = os.path.abspath(str(path))
    if norm_key in seen:
        continue
    seen.add(norm_key)
    try:
        s = path.stat()
    except FileNotFoundError:
        if path.is_symlink():
            found = True
            emit('unknown', label + ': broken config symlink',
                 f'Inspect symlink with ls -l "{path}"; see https://iscooked.com/unknowns#configuration')
        continue
    except OSError:
        found = True
        emit('unknown', label + ': configuration is inaccessible',
             f'Check permissions with ls -ld "{path}"; see https://iscooked.com/unknowns#configuration')
        continue
    if not stat.S_ISREG(s.st_mode) or s.st_size > LIMIT:
        found = True
        emit('unknown', label + ': unsupported file type or configuration exceeds 1 MiB limit',
             'Ensure MCP config is a regular file under 1 MiB; see https://iscooked.com/unknowns#configuration')
        continue
    try:
        # O_NONBLOCK prevents a raced FIFO from blocking the scanner.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError()
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError()
        data = parse_toml(raw) if schema_kind == 'codex_toml' else parse_jsonc(raw)
        if not isinstance(data, dict):
            raise ValueError()
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        found = True
        emit('unknown', label + ': unreadable, malformed, or oversized configuration',
             f'Validate syntax of "{path}"; see https://iscooked.com/unknowns#configuration')
        continue

    groups = []
    if schema_kind == 'mcpServers':
        if 'mcpServers' in data:
            groups.append(data['mcpServers'])
    elif schema_kind == 'claude_user':
        if 'mcpServers' in data:
            groups.append(data['mcpServers'])
        if isinstance(data.get('projects'), dict):
            projects = list(data['projects'].values())
            if len(projects) > 128:
                found = True
                emit('unknown', label + ': project limit exceeded; inspection incomplete',
                     'Clean unused project entries in ~/.claude.json; see https://iscooked.com/unknowns#configuration')
            for project in projects[:128]:
                if isinstance(project, dict) and 'mcpServers' in project:
                    groups.append(project['mcpServers'])
    elif schema_kind == 'opencode_mcp':
        if 'mcp' in data:
            groups.append(data['mcp'])
    elif schema_kind == 'zed_context_servers':
        if 'context_servers' in data:
            groups.append(data['context_servers'])
    elif schema_kind == 'vscode_servers':
        if 'servers' in data:
            groups.append(data['servers'])
        if 'mcpServers' in data:
            groups.append(data['mcpServers'])
    elif schema_kind == 'codex_toml':
        if 'mcp_servers' in data:
            groups.append(data['mcp_servers'])

    if not groups:
        if strict_mcp_file and 'servers' in data:
            found = True
            emit('unknown', label + ': uses a "servers" format this scanner does not evaluate yet',
                 'Use standard mcpServers object or check VS Code .vscode/mcp.json; see https://iscooked.com/unknowns#configuration')
        elif strict_mcp_file or schema_kind == 'claude_user':
            found = True
            if not permissions(path, label, False):
                emit('safe', label + ': no MCP servers configured')
        continue

    found = True
    file_emitted = False
    servers = []
    for group in groups:
        if isinstance(group, dict):
            servers.extend(group.values())
        else:
            emit('unknown', label + ': unsupported MCP server structure',
                 'Expected a JSON/TOML object mapping server names to configurations; see https://iscooked.com/unknowns#configuration')
            file_emitted = True

    credentials = any(has_credentials(s) for s in servers if isinstance(s, dict))
    if project_local and credentials:
        emit('warming', label + ': project-local MCP configuration contains hardcoded credential values',
             'Move secrets out of repository MCP files into environment variables (e.g. ${API_KEY})')
        file_emitted = True
    if permissions(path, label, credentials):
        file_emitted = True
    if len(servers) > 128:
        emit('unknown', label + ': server limit exceeded; inspection incomplete',
             'Reduce server count below 128; see https://iscooked.com/unknowns#configuration')
        file_emitted = True
    for i, server in enumerate(servers[:128], 1):
        if inspect_server(server, label + ' server ' + str(i)):
            file_emitted = True
    if not file_emitted:
        if servers:
            emit('safe', label + ': ' + str(len(servers)) + ' MCP server(s) reviewed; no risky settings found')
        else:
            emit('safe', label + ': no MCP servers configured')
if not found:
    emit('skip', 'No supported MCP configuration found; unsupported clients and formats are not evaluated')
MCP_PY
    ); then
        result_unknown "MCP configuration parser failed; inspection incomplete" "Inspect MCP configuration JSON/TOML files manually; see https://iscooked.com/unknowns#configuration"
        return
    fi
    while IFS=$'\t' read -r mcp_severity mcp_message mcp_hint; do
        case "$mcp_severity" in
            cooked) result_cooked "$mcp_message" "$mcp_hint" ;;
            warming) result_warming "$mcp_message" "$mcp_hint" ;;
            safe) result_safe "$mcp_message" ;;
            unknown) result_unknown "$mcp_message" "$mcp_hint" ;;
            skip) result_skip "$mcp_message" ;;
        esac
    done <<< "$mcp_output"
}

check_agent_gateway() {
    section "15" "Coding Agent Permissions & Gateways"
    if ! command -v python3 >/dev/null 2>&1; then
        result_skip "Coding agent and OpenClaw configuration inspection requires optional python3"
        return
    fi
    local gateway_output gateway_severity gateway_message gateway_hint
    if ! gateway_output=$(python3 -I -B -S - 2>/dev/null <<'GATEWAY_PY'
import fnmatch
import glob
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

LIMIT = 1048576
COMMENT_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/')
COMMA_RE = re.compile(r'"(?:\\.|[^"\\])*"|(,)(\s*[}\]])')
home = Path.home()
cwd = Path.cwd()
any_found = False


def emit(level, message, hint=''):
    print(level + '\t' + message + '\t' + hint)


def strip_jsonc(text):
    stripped = COMMENT_RE.sub(lambda m: m.group(0) if m.group(0).startswith('"') else ' ', text)
    return COMMA_RE.sub(lambda m: m.group(2) if m.group(1) else m.group(0), stripped)


def parse_jsonc(raw_bytes, *, object_pairs_hook=None, parse_constant=None):
    cleaned = strip_jsonc(raw_bytes.decode('utf-8-sig'))
    return json.loads(cleaned, object_pairs_hook=object_pairs_hook, parse_constant=parse_constant)


def _strip_toml_comment(line):
    in_dq = False
    in_sq = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if in_dq:
            if ch == '\\':
                escaped = True
            elif ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == '#':
                return line[:idx]
    return line


def _parse_toml_scalar(val):
    val = val.strip()
    if val == 'true':
        return True
    if val == 'false':
        return False
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        return json.loads(val)
    if val.startswith("'") and val.endswith("'") and len(val) >= 2:
        return val[1:-1]
    return val


def parse_toml(raw_bytes):
    text = raw_bytes.decode('utf-8-sig')
    if tomllib is not None:
        return tomllib.loads(text)
    root = {}
    cursor = root
    for raw_line in text.splitlines():
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            header = line[1:-1].strip()
            parts = [p.strip().strip('"\'') for p in header.split('.')]
            cursor = root
            for part in parts:
                if part not in cursor or not isinstance(cursor[part], dict):
                    cursor[part] = {}
                cursor = cursor[part]
        elif '=' in line:
            k, _, v = line.partition('=')
            cursor[k.strip().strip('"\'')] = _parse_toml_scalar(v)
    return root


def read_regular_bytes(path, label, *, nofollow=False):
    global any_found
    try:
        before = os.lstat(path) if nofollow else os.stat(path)
    except FileNotFoundError:
        if not nofollow and os.path.islink(path):
            any_found = True
            emit('unknown', f'{label}: broken configuration symlink',
                 f'Inspect symlink with ls -l "{path}"; see https://iscooked.com/unknowns#configuration')
        return None
    except OSError:
        any_found = True
        emit('unknown', f'{label}: configuration inaccessible; inspection incomplete',
             f'Check permissions with ls -ld "{path}"; see https://iscooked.com/unknowns#configuration')
        return None
    any_found = True
    try:
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o444 or before.st_size > LIMIT:
            raise ValueError()
        flags = os.O_RDONLY | os.O_NONBLOCK
        if nofollow:
            flags |= getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError()
            raw = stream.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError()
        return raw
    except (OSError, ValueError):
        emit('unknown', f'{label}: unreadable, oversized, or unsupported file type',
             f'Inspect "{path}" with ls -l; see https://iscooked.com/unknowns#configuration')
        return None


# ── 1. OpenClaw Gateway & Policy ─────────────────────────────────────────────
def object_at(obj, key):
    value = obj.get(key, {})
    if not isinstance(value, dict):
        raise ValueError()
    return value


def enum(obj, key, values):
    if key in obj and (not isinstance(obj[key], str) or obj[key] not in values):
        raise ValueError()
    return obj.get(key)


def strings(obj, key):
    value = obj.get(key, [])
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise ValueError()
    return value


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError()
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError()


def unresolved(value):
    if isinstance(value, dict):
        return '$include' in value or any(unresolved(v) for v in value.values())
    if isinstance(value, list):
        return any(unresolved(v) for v in value)
    return isinstance(value, str) and '${' in value


def check_openclaw():
    path = os.environ.get('OPENCLAW_CONFIG_PATH') or os.path.join(str(home), '.openclaw', 'openclaw.json')
    raw = read_regular_bytes(path, 'OpenClaw', nofollow=True)
    if raw is None:
        return
    oc_emitted = False
    try:
        config = parse_jsonc(raw, object_pairs_hook=unique, parse_constant=reject_constant)
        if not isinstance(config, dict) or unresolved(config):
            raise ValueError()
        gateway = object_at(config, 'gateway')
        auth = object_at(gateway, 'auth')
        bind = enum(gateway, 'bind', ('auto', 'loopback', 'lan', 'tailnet', 'custom'))
        enum(gateway, 'mode', ('local', 'remote'))
        auth_mode = enum(auth, 'mode', ('none', 'token', 'password', 'trusted-proxy'))
        exposed = bind == 'lan'
        if bind == 'custom':
            host = gateway.get('customBindHost')
            if not isinstance(host, str):
                raise ValueError()
            exposed = not ipaddress.IPv4Address(host).is_loopback
        if bind in ('auto', 'tailnet') and auth_mode == 'none':
            emit('unknown', 'OpenClaw: bind requires runtime resolution; exposure with disabled auth cannot be determined',
                 'Bind gateway to loopback or enable token/password auth; see https://iscooked.com/unknowns#configuration')
            oc_emitted = True
        elif exposed and auth_mode == 'none' and gateway.get('mode') != 'remote':
            emit('cooked', 'OpenClaw: configuration exposes gateway beyond localhost with authentication explicitly disabled; verify runtime and upstream controls',
                 'Set gateway.bind to loopback and enable gateway.auth.mode token or password')
            oc_emitted = True
        elif auth_mode in ('token', 'password', 'trusted-proxy'):
            emit('safe', 'OpenClaw: gateway auth mode is configured (runtime enforcement not verified)')
            oc_emitted = True

        agents = object_at(config, 'agents')
        defaults = object_at(agents, 'defaults')
        sandbox = object_at(defaults, 'sandbox')
        sandbox_mode = enum(sandbox, 'mode', ('off', 'non-main', 'all'))
        tools = object_at(config, 'tools')
        execute = object_at(tools, 'exec')
        exec_mode = enum(execute, 'mode', ('deny', 'allowlist', 'ask', 'auto', 'full'))
        security = enum(execute, 'security', ('deny', 'allowlist', 'full'))
        ask = enum(execute, 'ask', ('off', 'on-miss', 'always'))
        host = enum(execute, 'host', ('auto', 'sandbox', 'gateway', 'node'))
        if exec_mode is not None and ('security' in execute or 'ask' in execute):
            raise ValueError()
        profile = enum(tools, 'profile', ('minimal', 'messaging', 'coding', 'full'))
        allow, deny, additional = (strings(tools, key) for key in ('allow', 'deny', 'alsoAllow'))
        if 'allow' in tools and 'alsoAllow' in tools:
            raise ValueError()
        channels = object_at(config, 'channels')
        if any(key in agents for key in ('entries', 'list')) or 'bindings' in config or any(key in tools for key in ('byProvider', 'toolsBySender')):
            raise ValueError()
        open_ingress = False
        for name, channel in channels.items():
            if not isinstance(channel, dict):
                raise ValueError()
            if 'enabled' in channel and not isinstance(channel['enabled'], bool):
                raise ValueError()
            if channel.get('enabled') is False:
                continue
            if name not in ('telegram', 'whatsapp') or any(key in channel for key in ('accounts', 'tools', 'toolsBySender', 'groups')):
                raise ValueError()
            policy = enum(channel, 'dmPolicy', ('open', 'pairing', 'allowlist', 'disabled'))
            incoming = strings(channel, 'allowFrom')
            open_ingress |= policy == 'open' and '*' in incoming

        def matches(patterns):
            return any(p.lower() == 'group:runtime' or fnmatch.fnmatchcase('exec', p.lower()) or p.lower() == 'bash' for p in patterns)

        capability = profile in ('coding', 'full') or matches(additional) or (profile is None and matches(allow))
        if 'allow' in tools:
            capability = capability and matches(allow)
        capability = capability and not matches(deny)
        permissive_exec = exec_mode == 'full' or (exec_mode is None and security == 'full' and ask == 'off')
        host_exec = host == 'gateway' or (host in (None, 'auto') and sandbox_mode == 'off')
        if open_ingress and capability and permissive_exec and host_exec and sandbox_mode == 'off':
            emit('cooked', 'OpenClaw: open DM ingress combines with configured unrestricted host exec and disabled sandbox; host approvals and runtime enforcement remain unverified',
                 'Enable sandbox mode, restrict DM allowFrom/dmPolicy, and require exec approvals')
            oc_emitted = True
        elif permissive_exec or sandbox_mode == 'off':
            emit('warming', 'OpenClaw: explicit permissive exec or disabled sandbox setting; review request access and host approval policy',
                 'Enable sandbox.mode and restrict tools.exec approvals')
            oc_emitted = True
        elif not oc_emitted:
            emit('safe', 'OpenClaw: no unsafe gateway exposure or tool-policy combination found')
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        emit('unknown', 'OpenClaw: configuration unreadable, oversized, malformed or unsupported (JSON/JSONC and known policy fields only); inspection incomplete',
             'Review ~/.openclaw/openclaw.json manually; see https://iscooked.com/unknowns#configuration')


# ── 2. Claude Code Settings & Hooks ──────────────────────────────────────────
def path_or_parent_world_writable(target):
    try:
        resolved = Path(target).resolve(strict=True)
        if resolved.stat().st_mode & stat.S_IWOTH:
            return True
        return any(p.stat().st_mode & stat.S_IWOTH and not p.stat().st_mode & stat.S_ISVTX
                   for p in resolved.parents)
    except OSError:
        return False


def extract_hook_commands(hooks_obj):
    commands = []
    if not isinstance(hooks_obj, dict):
        return commands
    for event_entries in hooks_obj.values():
        if not isinstance(event_entries, list):
            continue
        for entry in event_entries:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get('command'), str):
                commands.append(entry['command'])
            inner = entry.get('hooks')
            if isinstance(inner, list):
                for item in inner:
                    if isinstance(item, dict) and isinstance(item.get('command'), str):
                        commands.append(item['command'])
    return commands


def check_claude_code():
    candidates = [
        (home / '.claude/settings.json', 'Claude Code (user)', False),
        (home / '.claude/settings.local.json', 'Claude Code (user local)', False),
        (cwd / '.claude/settings.json', 'Claude Code (project)', True),
        (cwd / '.claude/settings.local.json', 'Claude Code (project local)', True),
    ]
    seen = set()
    for path, label, is_project in candidates:
        key = os.path.abspath(str(path))
        if key in seen:
            continue
        seen.add(key)
        raw = read_regular_bytes(path, label)
        if raw is None:
            continue
        try:
            data = parse_jsonc(raw)
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeDecodeError, RecursionError):
            emit('unknown', f'{label}: malformed settings JSON',
                 f'Validate syntax of "{path}"; see https://iscooked.com/unknowns#configuration')
            continue

        emitted = False
        perms = data.get('permissions', {})
        if isinstance(perms, dict):
            if perms.get('defaultMode') == 'bypassPermissions':
                emit('cooked', f'{label}: permissions.defaultMode is set to bypassPermissions',
                     f'Remove "defaultMode": "bypassPermissions" from "{path}"')
                emitted = True
            allow = perms.get('allow', [])
            if isinstance(allow, list):
                crit_rules = []
                warn_rules = []
                for rule in allow:
                    if not isinstance(rule, str):
                        continue
                    r = rule.strip()
                    if r in ('Bash', 'Bash(*)', 'Bash(:*)', 'Bash(* *)', 'Bash(*:*)') or re.fullmatch(r'Bash\(sudo(?:\s+|:)\*\)', r):
                        crit_rules.append(r)
                    elif re.fullmatch(r'Bash\((?:rm|curl|wget|sh|bash)(?:\s+|:)[^)]*\*\)', r):
                        warn_rules.append(r)
                if crit_rules:
                    emit('cooked', f'{label}: unrestricted shell allowlist ({", ".join(crit_rules)})',
                         'Remove wildcard Bash(*) / Bash / Bash(sudo *) entries from permissions.allow')
                    emitted = True
                if warn_rules:
                    emit('warming', f'{label}: broad dangerous shell allowlist ({", ".join(warn_rules)})',
                         'Narrow wildcard Bash allowlist rules to specific safe commands')
                    emitted = True

        hooks = data.get('hooks')
        hook_cmds = extract_hook_commands(hooks)
        if hook_cmds:
            writable_script = False
            for cmd in hook_cmds:
                try:
                    exe = shlex.split(cmd)[0]
                except ValueError:
                    exe = cmd.split()[0] if cmd.split() else ''
                if not exe:
                    continue
                candidate = Path(os.path.expanduser(exe))
                if not candidate.is_absolute():
                    candidate = (cwd if is_project else home) / candidate
                if path_or_parent_world_writable(candidate):
                    writable_script = True
                    break
            if writable_script:
                emit('cooked', f'{label}: configured shell hook script is world-writable or in a world-writable directory',
                     'Fix hook script permissions (chmod 750) and restrict directory write access')
                emitted = True
            elif is_project:
                emit('warming', f'{label}: project-level shell hooks configured; review hook commands before trusting repository',
                     f'Inspect hooks in "{path}" before running Claude Code in this project')
                emitted = True

        if not emitted:
            emit('safe', f'{label}: permissions configuration passed checks')


# ── 3. OpenCode Permissions ──────────────────────────────────────────────────
def _is_opencode_allow(val):
    return val == 'allow' or (isinstance(val, dict) and val.get('*') == 'allow')


def check_opencode():
    candidates = [
        (home / '.config/opencode/opencode.json', 'OpenCode (user)'),
        (cwd / 'opencode.json', 'OpenCode (project)'),
    ]
    seen = set()
    for path, label in candidates:
        key = os.path.abspath(str(path))
        if key in seen:
            continue
        seen.add(key)
        raw = read_regular_bytes(path, label)
        if raw is None:
            continue
        try:
            data = parse_jsonc(raw)
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeDecodeError, RecursionError):
            emit('unknown', f'{label}: malformed configuration JSON',
                 f'Validate syntax of "{path}"; see https://iscooked.com/unknowns#configuration')
            continue

        perm = data.get('permission')
        emitted = False
        if perm == 'allow' or (isinstance(perm, dict) and perm.get('*') == 'allow'):
            emit('cooked', f'{label}: wildcard permission "*" is set to "allow"',
                 'Change permission "*" to "ask" or restrict individual tools')
            emitted = True
        elif isinstance(perm, dict):
            bash_allow = _is_opencode_allow(perm.get('bash'))
            ext_allow = _is_opencode_allow(perm.get('external_directory'))
            if bash_allow and ext_allow:
                emit('cooked', f'{label}: both bash and external_directory permissions are set to allow',
                     'Set permission.bash and permission.external_directory to "ask"')
                emitted = True
            elif bash_allow:
                emit('warming', f'{label}: bash permission is set to allow without prompt',
                     'Set permission.bash to "ask"')
                emitted = True
            elif ext_allow:
                emit('warming', f'{label}: external_directory permission is set to allow',
                     'Set permission.external_directory to "ask"')
                emitted = True

        if not emitted:
            emit('safe', f'{label}: permission settings passed checks')


# ── 4. Codex CLI ─────────────────────────────────────────────────────────────
def check_codex():
    path = home / '.codex/config.toml'
    raw = read_regular_bytes(path, 'Codex CLI')
    if raw is None:
        return
    try:
        data = parse_toml(raw)
        if not isinstance(data, dict):
            raise ValueError()
    except (ValueError, UnicodeDecodeError):
        emit('unknown', 'Codex CLI: malformed config.toml',
             f'Validate TOML syntax in "{path}"; see https://iscooked.com/unknowns#configuration')
        return
    approval = data.get('approval_policy')
    sandbox = data.get('sandbox_mode')
    if approval == 'never' and sandbox == 'danger-full-access':
        emit('cooked', 'Codex CLI: approval_policy="never" combined with sandbox_mode="danger-full-access"',
             'Set approval_policy = "on-request" and sandbox_mode = "workspace-write" in ~/.codex/config.toml')
    elif approval == 'never':
        emit('warming', 'Codex CLI: approval_policy is set to "never"',
             'Change approval_policy to "on-request" in ~/.codex/config.toml')
    elif sandbox == 'danger-full-access':
        emit('warming', 'Codex CLI: sandbox_mode is set to "danger-full-access"',
             'Change sandbox_mode to "workspace-write" in ~/.codex/config.toml')
    else:
        emit('safe', 'Codex CLI: approval and sandbox policy passed checks')


# ── 5. Cursor Auto-Run / YOLO Mode ───────────────────────────────────────────
def check_cursor():
    candidates = [
        (home / '.config/Cursor/User/settings.json', 'Cursor (Linux)'),
        (home / 'Library/Application Support/Cursor/User/settings.json', 'Cursor (macOS)'),
    ]
    for path, label in candidates:
        raw = read_regular_bytes(path, label)
        if raw is None:
            continue
        try:
            data = parse_jsonc(raw)
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeDecodeError, RecursionError):
            emit('unknown', f'{label}: malformed settings.json',
                 f'Validate syntax of "{path}"; see https://iscooked.com/unknowns#configuration')
            continue
        if (data.get('cursor.composer.shouldAutoRun') is True
                or data.get('cursor.composer.yoloMode') is True
                or data.get('yoloMode') is True):
            emit('warming', f'{label}: composer auto-run / YOLO mode is enabled',
                 'Disable cursor.composer.shouldAutoRun and yoloMode in Cursor settings')
        else:
            emit('safe', f'{label}: composer auto-run / YOLO mode is disabled')


# ── 6. Prompt-Injection Invisible Unicode Scan ───────────────────────────────
def count_invisible_unicode(text):
    count = 0
    for idx, ch in enumerate(text):
        cp = ord(ch)
        if (0x200B <= cp <= 0x200F
                or 0x202A <= cp <= 0x202E
                or 0x2060 <= cp <= 0x2069
                or (cp == 0xFEFF and idx > 0)
                or 0xE0000 <= cp <= 0xE007F):
            count += 1
    return count


def check_instruction_unicode():
    rel_paths = [
        'CLAUDE.md',
        'AGENTS.md',
        '.cursorrules',
        '.windsurfrules',
        '.github/copilot-instructions.md',
    ]
    mdc_files = sorted(glob.glob('.cursor/rules/*.mdc'))
    rel_paths.extend(mdc_files)
    scanned = 0
    found_dirty = False
    for rel in rel_paths:
        target = cwd / rel
        raw = read_regular_bytes(target, f'Instruction file {rel}')
        if raw is None:
            continue
        scanned += 1
        text = raw.decode('utf-8', errors='replace')
        hidden = count_invisible_unicode(text)
        if hidden > 0:
            found_dirty = True
            emit('cooked',
                 f'Instruction file {rel} contains {hidden} invisible/bidi Unicode character(s) (possible prompt injection)',
                 f'Inspect hidden codepoints in {rel} before trusting this repository')
    if scanned > 0 and not found_dirty:
        emit('safe', f'Checked {scanned} instruction file(s) in current directory; no hidden Unicode prompt-injection characters found')


check_openclaw()
check_claude_code()
check_opencode()
check_codex()
check_cursor()
check_instruction_unicode()

if not any_found:
    emit('skip', 'No OpenClaw, coding-agent settings, or instruction files found')
GATEWAY_PY
    ); then
        result_unknown "Coding agent and OpenClaw configuration parser failed; inspection incomplete" "Inspect agent configuration files manually; see https://iscooked.com/unknowns#configuration"
        return
    fi
    while IFS=$'\t' read -r gateway_severity gateway_message gateway_hint; do
        case "$gateway_severity" in
            cooked) result_cooked "$gateway_message" "$gateway_hint" ;;
            warming) result_warming "$gateway_message" "$gateway_hint" ;;
            safe) result_safe "$gateway_message" ;;
            unknown) result_unknown "$gateway_message" "$gateway_hint" ;;
            skip) result_skip "$gateway_message" ;;
        esac
    done <<< "$gateway_output"
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

    local evidence=false
    case "${OLLAMA_NO_CLOUD:-}" in
        1|true|TRUE|True|t|T)
            result_safe "OLLAMA_NO_CLOUD is enabled in the scanner environment; running service settings are not verified"
            evidence=true ;;
        ''|0|false|FALSE|False|f|F) ;;
        *) result_unknown "OLLAMA_NO_CLOUD has an unrecognized value; review the running service settings"; evidence=true ;;
    esac

    local do_not_track="${DO_NOT_TRACK:-}"
    if [[ "$do_not_track" == "1" ]]; then
        result_safe "DO_NOT_TRACK=1 is set in the scanner environment; application support and running service settings are not verified"
        evidence=true
    fi

    # Check /etc/hosts for blocked telemetry
    if [[ -f /etc/hosts ]]; then
        local blocked=0 domain
        # Compare complete host tokens, including aliases before a comment.
        if ! blocked=$(awk -v domains="$telemetry_domains_list" '
            BEGIN { n=split(domains, items, "\n"); for (i=1; i<=n; i++) wanted[items[i]]=1 }
            { sub(/#.*/, "") }
            $1 == "0.0.0.0" { for (i=2; i<=NF; i++) if ($i in wanted) seen[$i]=1 }
            END { for (name in seen) count++; print count+0 }
        ' /etc/hosts 2>/dev/null); then
            result_unknown "Telemetry hosts-file evidence is unavailable"
            evidence=true
            blocked=0
        fi
        if [[ $blocked -gt 0 ]]; then
            result_safe "${blocked} telemetry domains mapped to 0.0.0.0 in /etc/hosts; application DNS behavior is not verified"
            evidence=true
        fi
    fi
    if [[ "$evidence" == false ]]; then
        result_skip "No supported opt-out evidence found; outbound traffic and running service settings are not assessed"
    fi
}

check_firewall() {
    section "07" "Firewall Status"

    # A missing host firewall matters most when an AI service is reachable
    # beyond localhost. Backend states are gathered first, then reported as one
    # result whose severity follows that exposure.
    local has_firewall=false
    local inactive=() failed=()

    if [[ "$OS_TYPE" == macos ]]; then
        if ! command_exists /usr/libexec/ApplicationFirewall/socketfilterfw && ! command_exists pfctl; then
            failed+=("no supported firewall inspection tool is available")
        fi
    else
        # Check unprivileged Linux firewall state first before privileged commands.
        if command_exists systemctl; then
            if systemctl is-active --quiet ufw 2>/dev/null; then
                result_safe "UFW firewall service is active"
                has_firewall=true
            elif systemctl is-active --quiet firewalld 2>/dev/null; then
                result_safe "firewalld service is active"
                has_firewall=true
            elif systemctl is-active --quiet nftables 2>/dev/null; then
                result_safe "nftables service is active"
                has_firewall=true
            elif systemctl is-active --quiet iptables 2>/dev/null; then
                result_safe "iptables service is active"
                has_firewall=true
            fi
        fi
        if [[ "$has_firewall" == "false" && -r /etc/ufw/ufw.conf ]] \
            && grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes([[:space:]]|$|#)' /etc/ufw/ufw.conf 2>/dev/null; then
            result_safe "UFW firewall is enabled (/etc/ufw/ufw.conf)"
            has_firewall=true
        fi
        [[ "$has_firewall" == "true" ]] && return

        if ! command_exists ufw && ! command_exists firewall-cmd && ! command_exists iptables && ! command_exists nft; then
            failed+=("no supported firewall inspection tool is available")
        fi
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        # macOS Application Firewall (socketfilterfw)
        if command_exists /usr/libexec/ApplicationFirewall/socketfilterfw; then
            local fw_status
            if ! fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null); then
                failed+=("macOS Application Firewall status inspection failed")
            elif echo "$fw_status" | grep -qi "enabled"; then
                result_safe "macOS Application Firewall is enabled"
                has_firewall=true
            elif echo "$fw_status" | grep -qi "disabled"; then
                inactive+=("macOS Application Firewall is DISABLED")
            else
                failed+=("macOS Application Firewall returned an unrecognized status")
            fi
        fi

        # macOS pf (packet filter)
        if command_exists pfctl; then
            local pf_status
            if ! pf_status=$(pfctl -s info 2>/dev/null); then
                failed+=("macOS pf status inspection failed")
            elif echo "$pf_status" | grep -Eqi "^Status:[[:space:]]+Enabled([[:space:]]|$)"; then
                result_safe "macOS pf (packet filter) is enabled"
                has_firewall=true
            elif echo "$pf_status" | grep -Eqi "^Status:[[:space:]]+Disabled([[:space:]]|$)"; then
                inactive+=("macOS pf is disabled")
            else
                failed+=("macOS pf returned an unrecognized status")
            fi
        fi
    else
        # UFW
        if command_exists ufw; then
            local ufw_status
            if ! ufw_status=$(ufw status 2>/dev/null); then
                failed+=("UFW status inspection failed")
            elif echo "$ufw_status" | grep -Eqi "^Status:[[:space:]]+active$"; then
                result_safe "UFW firewall is active"
                has_firewall=true
            elif echo "$ufw_status" | grep -Eqi "^Status:[[:space:]]+inactive$"; then
                inactive+=("UFW is installed but INACTIVE")
            else
                failed+=("UFW returned an unrecognized status")
            fi
        fi

        # firewalld
        if command_exists firewall-cmd; then
            if firewall-cmd --state &>/dev/null; then
                result_safe "firewalld is active"
                has_firewall=true
            else
                local firewalld_rc=$?
                if [[ "$firewalld_rc" -eq 252 ]]; then
                    inactive+=("firewalld is installed but INACTIVE")
                else
                    failed+=("firewalld status inspection failed (exit ${firewalld_rc})")
                fi
            fi
        fi

        # iptables — check if any rules exist
        if command_exists iptables; then
            local iptables_rules rule_count
            if iptables_rules=$(iptables -L 2>/dev/null); then
                rule_count=$(printf '%s\n' "$iptables_rules" | grep -c -v -E "^Chain|^target|^$" || true)
                rule_count=$((rule_count + 0))
                if [[ "$rule_count" -gt 2 ]]; then
                    result_safe "iptables has ${rule_count} rules configured"
                    has_firewall=true
                else
                    inactive+=("iptables has minimal/no rules")
                fi
            else
                failed+=("iptables ruleset inspection failed")
            fi
        fi

        # nftables
        if command_exists nft; then
            local nft_output nft_rules
            if nft_output=$(nft list ruleset 2>/dev/null); then
                if [[ -z "$nft_output" ]]; then
                    nft_rules=0
                else
                    nft_rules=$(printf '%s\n' "$nft_output" | wc -l)
                fi
                nft_rules=$((nft_rules + 0))
                if [[ "$nft_rules" -gt 5 ]]; then
                    result_safe "nftables has rules configured"
                    has_firewall=true
                else
                    inactive+=("nftables has minimal/no rules")
                fi
            else
                failed+=("nftables ruleset inspection failed")
            fi
        fi
    fi

    # An active firewall settles it; other backends' states don't change that.
    [[ "$has_firewall" == "true" ]] && return

    local details="" item
    for item in ${inactive[@]+"${inactive[@]}"} ${failed[@]+"${failed[@]}"}; do
        details="${details:+${details}; }${item}"
    done

    local exposure exposure_rc=0
    exposure=$(ai_service_exposure) || exposure_rc=$?

    if [[ "${#failed[@]}" -gt 0 ]]; then
        if [[ "$exposure_rc" -eq 1 ]]; then
            result_skip "Firewall state could not be fully read (${details}); no AI service listens beyond localhost, so this does not affect your score. Re-run with sudo to check." "Check manually with sudo ufw status or sudo nft list ruleset"
        else
            result_unknown "Firewall state UNKNOWN (${details}). Re-run with sudo to check." "Run sudo ufw status, sudo nft list ruleset, or see https://iscooked.com/unknowns#firewall"
        fi
    elif [[ "$exposure_rc" -eq 0 ]]; then
        local exposure_cap
        exposure_cap=$(printf '%s%s' "$(printf '%s' "${exposure:0:1}" | tr '[:lower:]' '[:upper:]')" "${exposure:1}")
        result_cooked "No active firewall detected! ${exposure_cap} with nothing filtering it (${details})" "Enable ufw (sudo ufw enable), firewalld, nftables, or macOS Application Firewall"
    elif [[ "$exposure_rc" -eq 1 ]]; then
        result_warming "No active firewall detected (${details}). No AI service listens beyond localhost, so this is defense in depth rather than an open door." "Enable ufw (sudo ufw enable), firewalld, nftables, or macOS Application Firewall"
    else
        result_warming "No active firewall detected (${details}). Listening services could not be checked." "Enable ufw (sudo ufw enable), firewalld, nftables, or macOS Application Firewall"
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
8000
30000
4000"
    local found_http=false
    local listener_query_failed=false
    local listener_query_unavailable=false
    local probe_incomplete=false
    local listen_rc=0

    while IFS= read -r port; do
        local listen_line=""
        if listen_line=$(get_listen_line "$port"); then
            :
        else
            listen_rc=$?
            if [[ "$listen_rc" -eq 2 ]]; then
                listener_query_failed=true
            else
                listener_query_unavailable=true
            fi
            continue
        fi

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
                if ! is_numeric_ip_host "$probe_host"; then
                    result_unknown "Port ${port} has an unsupported listener address; plain HTTP probe skipped" "Check listener bind address with ss -tlnp; see https://iscooked.com/unknowns#network"
                    probe_incomplete=true
                    continue
                fi
                if command_exists curl; then
                    local http_code https_code
                    local probe_url_host
                    probe_url_host=$(format_http_host "$probe_host")
                    http_code=$(curl -q -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 --noproxy '*' "http://${probe_url_host}:${port}/" 2>/dev/null) || http_code="000"
                    if [[ "$http_code" =~ ^[0-9]{3}$ && "$http_code" != "000" ]]; then
                        local tls_hint="Terminate TLS with a reverse proxy (Caddy/nginx) or bind port ${port} to 127.0.0.1"
                        if [[ "$FULL_SCAN" == "true" ]] && is_exposed_critical_port "$port"; then
                            record_result critical "Port ${port} is exposed on ${exposure_desc} over plain HTTP (correlated with Check 01; +0 pts)" "$tls_hint" 0
                        else
                            result_cooked "Port ${port} is exposed on ${exposure_desc} over plain HTTP" "$tls_hint"
                        fi
                        found_http=true
                    else
                        https_code=$(curl -q -k -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 --noproxy '*' "https://${probe_url_host}:${port}/" 2>/dev/null) || https_code="000"
                        if [[ "$https_code" =~ ^[0-9]{3}$ && "$https_code" != "000" ]]; then
                            result_safe "Port ${port} serves HTTPS/TLS on ${exposure_desc}"
                        else
                            result_unknown "Port ${port} plain HTTP/HTTPS probe was inconclusive (http=${http_code:-unknown}, https=${https_code:-unknown})" "Probe manually with curl -vk https://${probe_url_host}:${port}/; see https://iscooked.com/unknowns#network"
                            probe_incomplete=true
                        fi
                    fi
                else
                    result_warming "Port ${port} is exposed on ${exposure_desc} (cannot verify TLS without curl)" "Install curl or verify TLS configuration on port ${port}"
                    found_http=true
                fi
            fi
        fi
    done <<< "$ports_list"

    if [[ "$listener_query_failed" == "true" ]]; then
        result_unknown "Network listener inspection failed — plain HTTP exposure status UNKNOWN"
    elif [[ "$listener_query_unavailable" == "true" ]]; then
        result_skip "Plain HTTP inspection requires ss or netstat"
    elif [[ "$found_http" == "false" && "$probe_incomplete" == "false" ]]; then
        result_safe "No AI services exposed over plain HTTP on non-localhost"
    fi
}

check_processes() {
    section "09" "AI Process Enumeration"

    local ai_process_patterns="ollama|llama[.]cpp|llama-server|text-generation|vllm|lmstudio|comfyui|stable-diffusion|koboldcpp|localai|whisper|faster-whisper|tabbyapi|sglang|litellm|openclaw|opencode|open-webui|mcp-server"

    if ! command_exists ps; then
        result_skip "Process inspection requires ps"
        return
    fi

    local ps_snapshot
    if ! ps_snapshot=$(ps aux 2>/dev/null); then
        result_unknown "AI process inspection failed — process state UNKNOWN" "Run ps -eo pid,user,comm; see https://iscooked.com/unknowns#network"
        return
    fi

    local ai_procs
    local my_pid=$$
    if ! ai_procs=$(printf '%s\n' "$ps_snapshot" | awk -v pid="$my_pid" -v re="$ai_process_patterns" \
        '$2 != pid && $0 !~ /^[[:space:]]*USER[[:space:]]/ && tolower($0) ~ re {print}'); then
        result_unknown "AI process filtering failed — process state UNKNOWN" "Run ps -eo pid,user,comm; see https://iscooked.com/unknowns#network"
        return
    fi

    if [[ -z "$ai_procs" ]]; then
        result_skip "No AI-related processes running"
        return
    fi

    while IFS= read -r proc_line; do
        local proc_user proc_pid proc_cmd
        proc_user=$(awk '{print $1}' <<< "$proc_line")
        proc_pid=$(awk '{print $2}' <<< "$proc_line")
        proc_cmd=$(awk '{print $11}' <<< "$proc_line")
        proc_cmd="${proc_cmd##*/}"
        proc_cmd="${proc_cmd:-unknown executable}"

        if [[ "$proc_user" == "root" ]]; then
            result_cooked "Candidate AI process '${proc_cmd}' (pid ${proc_pid}) running as root" "Run '${proc_cmd}' under a dedicated non-root user account"
        else
            result_safe "Candidate AI process '${proc_cmd}' (pid ${proc_pid}) running as '${proc_user}'"
        fi
    done <<< "$ai_procs"
}

check_sensitive_files() {
    section "10" "Sensitive File Exposure"

    # Check if .env in current directory is tracked by git
    if command_exists git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if git ls-files --error-unmatch .env >/dev/null 2>&1; then
            result_cooked ".env in current directory is tracked by git" "Untrack it with: git rm --cached .env && echo .env >> .gitignore"
        fi
    fi

    # Check .env files in common locations
    local search_dirs_list="$HOME
$HOME/Projects
$HOME/projects
$HOME/code
$HOME/dev
/opt
/srv"

    local found_exposed_env=false
    local env_inspection_incomplete=false
    local -a seen_env_files=()
    while IFS= read -r dir; do
        if [[ -d "$dir" ]]; then
            local env_files="" env_file_count=0
            if [[ "$dir" == "/opt" || "$dir" == "/srv" ]]; then
                [[ -r "$dir" && -x "$dir" ]] || continue
                if ! env_files=$(find "$dir" -maxdepth 3 \( -type d ! -readable -prune \) -o -type f \( -name ".env" -o -name ".env.local" -o -name "*.env" \) -print 2>/dev/null | awk 'NR <= 21 { print }'); then
                    continue
                fi
            elif ! env_files=$(find "$dir" -maxdepth 3 -type f \( -name ".env" -o -name ".env.local" -o -name "*.env" \) -print 2>/dev/null | awk 'NR <= 21 { print }'); then
                result_unknown "Sensitive file search incomplete in ${dir}" "Inspect permissions under ${dir}; see https://iscooked.com/unknowns#files"
                env_inspection_incomplete=true
                continue
            fi
            while IFS= read -r env_file; do
                [[ -z "$env_file" ]] && continue
                env_file_count=$((env_file_count + 1))
                if [[ "$env_file_count" -gt 20 ]]; then
                    result_skip "Sensitive file search reached the 20-file limit in ${dir}; additional files were not examined"
                    env_inspection_incomplete=true
                    break
                fi
                local already_seen=false seen_env_file
                if [[ "${#seen_env_files[@]}" -gt 0 ]]; then
                    for seen_env_file in "${seen_env_files[@]}"; do
                        if [[ "$seen_env_file" == "$env_file" ]]; then
                            already_seen=true
                            break
                        fi
                    done
                fi
                if [[ "$already_seen" == "true" ]]; then
                    continue
                fi
                seen_env_files+=("$env_file")
                if [[ -f "$env_file" ]]; then
                    local perms
                    if ! perms=$(get_file_perms "$env_file"); then
                        result_unknown "Permission inspection failed for ${env_file}" "Run ls -ld \"${env_file}\"; see https://iscooked.com/unknowns#files"
                        env_inspection_incomplete=true
                        continue
                    fi
                    if [[ ! "$perms" =~ ^[0-7]+$ ]]; then
                        result_unknown "Permission inspection returned an invalid value for ${env_file}" "Run ls -ld \"${env_file}\"; see https://iscooked.com/unknowns#files"
                        env_inspection_incomplete=true
                        continue
                    fi
                    if (( (8#$perms & 4) != 0 )); then
                        if grep -qiE '(api_key|api_secret|token|password|secret)=' "$env_file" 2>/dev/null; then
                            result_cooked ".env file with API keys is world-readable: ${env_file} (mode ${perms})" "Restrict permissions: chmod 600 \"${env_file}\""
                            found_exposed_env=true
                        else
                            local env_grep_rc=$?
                            if [[ "$env_grep_rc" -gt 1 ]]; then
                                result_unknown "Secret scan failed for ${env_file}" "Check readability with ls -ld \"${env_file}\"; see https://iscooked.com/unknowns#files"
                                env_inspection_incomplete=true
                            fi
                        fi
                    fi
                fi
            done <<< "$env_files"
        fi
    done <<< "$search_dirs_list"

    if [[ "$found_exposed_env" == "false" && "$env_inspection_incomplete" == "false" ]]; then
        result_safe "No world-readable .env files with API keys found"
    fi

    # Check permissions on coding-agent and dev credential stores (never print contents)
    local cred_stores_list="$HOME/.claude/.credentials.json
$HOME/.config/opencode/auth.json
$HOME/.codex/auth.json
$HOME/.config/gh/hosts.yml
$HOME/.aws/credentials
$HOME/.netrc
$HOME/.ssh/id_rsa
$HOME/.ssh/id_ed25519"
    local private_cred_count=0
    while IFS= read -r cred_file; do
        [[ -n "$cred_file" && -f "$cred_file" ]] || continue
        local cperms
        if ! cperms=$(get_file_perms "$cred_file"); then
            result_unknown "Permission inspection failed for ${cred_file}" "Run ls -ld \"${cred_file}\"; see https://iscooked.com/unknowns#files"
            continue
        fi
        if [[ ! "$cperms" =~ ^[0-7]+$ ]]; then
            result_unknown "Permission inspection returned an invalid value for ${cred_file}" "Run ls -ld \"${cred_file}\"; see https://iscooked.com/unknowns#files"
            continue
        fi
        if (( (8#$cperms & 6) != 0 )); then
            result_cooked "Credential store ${cred_file} is world-readable or world-writable (mode ${cperms})" "Restrict permissions: chmod 600 \"${cred_file}\""
        elif (( (8#$cperms & 48) != 0 )); then
            result_warming "Credential store ${cred_file} is group-readable or group-writable (mode ${cperms})" "Restrict permissions: chmod 600 \"${cred_file}\""
        else
            private_cred_count=$((private_cred_count + 1))
        fi
    done <<< "$cred_stores_list"
    if [[ "$private_cred_count" -gt 0 ]]; then
        result_safe "${private_cred_count} coding-agent/dev credential store(s) have private permissions (mode 600/400)"
    fi

    # Check if models directory is owned properly
    if [[ -d "$HOME/.ollama" ]]; then
        local ollama_owner
        if ! ollama_owner=$(get_file_owner "$HOME/.ollama"); then
            result_unknown "~/.ollama owner inspection failed" "Run ls -ld ~/.ollama; see https://iscooked.com/unknowns#files"
        elif [[ -z "$ollama_owner" || "$ollama_owner" == "unknown" ]]; then
            result_unknown "~/.ollama owner is UNKNOWN" "Run ls -ld ~/.ollama; see https://iscooked.com/unknowns#files"
        elif [[ "$ollama_owner" != "$(whoami)" && "$ollama_owner" != "ollama" ]]; then
            result_warming "~/.ollama is owned by '${ollama_owner}' instead of you" "Fix ownership with chown -R \"$(whoami)\" ~/.ollama"
        fi
    fi
}

check_history_logs() {
    section "11" "History & Logs Leakage"

    # Check shell history for API keys
    local history_files_list="$HOME/.bash_history
$HOME/.zsh_history
$HOME/.local/share/fish/fish_history"

    local inspected_any=false
    while IFS= read -r hist_file; do
        if [[ -f "$hist_file" ]]; then
            inspected_any=true
            local key_leaks=""
            local history_grep_failed=false
            if key_leaks=$(grep -ciE '(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9_-]{10,}|sk-proj-[a-zA-Z0-9_-]{10,}|sk-or-[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{10,}|github_pat_[a-zA-Z0-9_]{10,}|hf_[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16}|api_key=|OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|HF_TOKEN)' "$hist_file" 2>/dev/null); then
                :
            else
                local history_grep_rc=$?
                if [[ "$history_grep_rc" -eq 1 ]]; then
                    key_leaks=0
                else
                    result_unknown "Shell history inspection failed for $(basename "$hist_file")" "Check permissions on ${hist_file}; see https://iscooked.com/unknowns#files"
                    history_grep_failed=true
                fi
            fi
            if [[ "$history_grep_failed" == "false" && ! "$key_leaks" =~ ^[0-9]+$ ]]; then
                result_unknown "Shell history inspection returned an invalid count for $(basename "$hist_file")" "Inspect ${hist_file} manually; see https://iscooked.com/unknowns#files"
                history_grep_failed=true
            fi
            if [[ "$history_grep_failed" == "false" && "$key_leaks" -gt 0 ]]; then
                result_cooked "Shell history contains ~${key_leaks} potential API key(s): $(basename "$hist_file")" "Rotate exposed keys and scrub matching lines from $(basename "$hist_file")"
            elif [[ "$history_grep_failed" == "false" ]]; then
                result_safe "No API keys found in $(basename "$hist_file")"
            fi

            # Check permissions on history file
            local hist_perms
            if ! hist_perms=$(get_file_perms "$hist_file"); then
                result_unknown "Permission inspection failed for $(basename "$hist_file")" "Run ls -ld \"${hist_file}\"; see https://iscooked.com/unknowns#files"
            elif [[ ! "$hist_perms" =~ ^[0-7]+$ ]]; then
                result_unknown "Permission inspection returned an invalid value for $(basename "$hist_file")" "Run ls -ld \"${hist_file}\"; see https://iscooked.com/unknowns#files"
            elif (( (8#$hist_perms & 4) != 0 )); then
                result_warming "$(basename "$hist_file") is world-readable (mode ${hist_perms})" "Restrict permissions: chmod 600 \"${hist_file}\""
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
            inspected_any=true
            local log_perms
            if ! log_perms=$(get_file_perms "$log_dir"); then
                result_unknown "Permission inspection failed for ${log_dir}" "Run ls -ld \"${log_dir}\"; see https://iscooked.com/unknowns#files"
            elif [[ ! "$log_perms" =~ ^[0-7]+$ ]]; then
                result_unknown "Permission inspection returned an invalid value for ${log_dir}" "Run ls -ld \"${log_dir}\"; see https://iscooked.com/unknowns#files"
            elif (( (8#$log_perms & 4) != 0 )); then
                result_warming "AI log directory is world-readable: ${log_dir}" "Restrict permissions: chmod 700 \"${log_dir}\""
            else
                result_safe "AI log directory has restrictive permissions: ${log_dir}"
            fi
        fi
    done <<< "$log_dirs_list"

    if [[ "$inspected_any" == "false" ]]; then
        result_skip "No shell history or AI log files found; nothing to inspect"
    fi
}

# ─── Check 16: Remote Model Code ──────────────────────────────────────────────

_model_code_snapshot() {
    # Only stdlib process inspection: never import model packages or read configs.
    # ps cannot preserve argv boundaries perfectly; malformed/indirect launches
    # are not treated as proof of a disabled setting. Cap bytes, rows, and time.
    python3 -I -B -S - <<'PY'
import os
import re
import select
import shlex
import subprocess
import time


def snapshot():
    proc = subprocess.Popen(['ps', '-ww', '-eo', 'pid=,args='],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    deadline = time.monotonic() + 3
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([proc.stdout], [], [], left)[0]:
                raise ValueError('timeout')
            chunk = os.read(proc.stdout.fileno(), min(65536, 1048577 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 1048576:
                raise ValueError('limit')
        if proc.wait(timeout=max(.01, deadline - time.monotonic())):
            raise ValueError('ps failed')
        lines = data.decode('utf-8', errors='replace').splitlines()
        if len(lines) > 8192:
            raise ValueError('row limit')
        return lines
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


def identity(tokens):
    if not tokens:
        return None
    exe = os.path.basename(tokens[0])
    if exe == 'vllm' and tokens[1:2] == ['serve']:
        return 'vLLM'
    if re.fullmatch(r'python(?:3(?:\.\d+)?)?', exe):
        if tokens[1:3] == ['-m', 'vllm.entrypoints.openai.api_server']:
            return 'vLLM'
        # Installed console scripts commonly appear as python /venv/bin/vllm.
        if len(tokens) >= 3 and os.path.basename(tokens[1]) == 'vllm' and tokens[2] == 'serve':
            return 'vLLM'
    if exe == 'text-generation-launcher':
        return 'TGI'
    if re.fullmatch(r'python(?:3(?:\.\d+)?)?', exe) and tokens[1:3] == ['-m', 'sglang.launch_server']:
        return 'SGLang'
    return None


def inspect(command):
    # Keep the already parsed identity when a later quote is malformed.
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    tokens = []
    malformed = False
    try:
        for token in lexer:
            tokens.append(token)
    except ValueError:
        malformed = True
    service = identity(tokens)
    if service is None:
        return None
    if malformed:
        return service, 'unknown'
    settings = []
    revisions = []
    indirect = False
    for i, token in enumerate(tokens):
        name, sep, value = token.partition('=')
        if name in ('--config', '--config-file'):
            indirect = True
        if name == '--no-trust-remote-code':
            settings.append(False if not sep else None)
        elif name == '--trust-remote-code':
            if not sep:
                value = tokens[i + 1] if i + 1 < len(tokens) and not tokens[i + 1].startswith('--') else 'true'
            settings.append({'true': True, '1': True, 'yes': True, 'on': True,
                             'false': False, '0': False, 'no': False, 'off': False}.get(value.lower()))
        elif name == '--code-revision':
            if not sep:
                value = tokens[i + 1] if i + 1 < len(tokens) else ''
            revisions.append(value)
    if indirect or None in settings or len(set(settings)) > 1:
        return service, 'unknown'
    if not settings:
        return service, 'absent'
    if not settings[0]:
        return service, 'disabled'
    # vLLM exposes a separate code revision. TGI's --revision is not enough
    # to prove the revision of separately referenced executable code.
    pinned = service == 'vLLM' and len(revisions) == 1 and re.fullmatch(r'[0-9a-fA-F]{40}', revisions[0])
    return service, 'pinned' if pinned else 'enabled'


try:
    lines = snapshot()
    results = []
    for line in lines:
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r'[0-9]{1,10}', parts[0]):
            if line.strip():
                raise ValueError('invalid ps row')
            continue
        found = inspect(parts[1])
        if found:
            results.append((found[1], found[0], parts[0]))
    for row in results:
        print('|'.join(row))
except Exception:
    # Exception text may contain command arguments: intentionally suppress it.
    print('unavailable|runtime|0')
PY
}

check_model_code_execution() {
    section "16" "Remote Model Code"
    if ! command_exists python3; then
        result_skip "Model code inspection unavailable: optional python3 is required to inspect launch arguments."
        return
    fi
    local snapshot state service pid found=false
    if ! snapshot=$(_model_code_snapshot 2>/dev/null); then
        result_unknown "Model code inspection unavailable; review active runtime settings." "Check active vLLM/TGI/SGLang launch flags; see https://iscooked.com/unknowns#runtime"
        return
    fi
    while IFS='|' read -r state service pid; do
        [[ -z "$state" ]] && continue
        found=true
        case "$state" in
            unavailable)
                result_unknown "Model code inspection unavailable; review active runtime settings." "Check active vLLM/TGI/SGLang launch flags; see https://iscooked.com/unknowns#runtime" ;;
            unknown)
                result_unknown "$service PID $pid: could not establish active remote-code configuration from launch arguments; review runtime settings and code." "Inspect runtime config for --trust-remote-code; see https://iscooked.com/unknowns#runtime" ;;
            absent)
                result_skip "$service PID $pid: no explicit remote-code launch setting observed; configuration, environment overrides and runtime behavior are not inspected." ;;
            disabled)
                result_skip "$service PID $pid: launch setting explicitly disables trust-remote-code; runtime behavior is not verified." ;;
            pinned)
                result_warming "$service PID $pid allows remote model code (--trust-remote-code); an immutable code revision is specified (+4). Review the executable code: a pin does not prove safety." "Remove --trust-remote-code if not required, or audit the pinned revision" ;;
            enabled)
                result_warming "$service PID $pid allows remote model code (--trust-remote-code) without a verified immutable code revision (+4). Review executable code and pin its revision; a model weights --revision alone is insufficient." "Remove --trust-remote-code or pin an audited 40-char --code-revision commit" ;;
            *)
                result_unknown "Model code inspection unavailable; review active runtime settings." "Check active vLLM/TGI/SGLang launch flags; see https://iscooked.com/unknowns#runtime" ;;
        esac
    done <<< "$snapshot"
    if [[ "$found" == false ]]; then
        result_skip "No supported active vLLM, TGI or SGLang launch found; config files, environment overrides and other runtimes are not inspected."
    fi
}

# ─── Check 17: Runtime Versions ───────────────────────────────────────────────

# Minimum versions that fix the reviewed advisories. Refresh this table and the
# reviewed date when new advisories land: service|port|route|minimum|advisories
RUNTIME_VERSIONS_REVIEWED="2026-11-20"
RUNTIME_MIN_VERSIONS="Ollama|11434|/api/version|0.35.0|CVE-2026-103663, CVE-2026-108836
vLLM|8000|/version|0.34.0|CVE-2026-115912, CVE-2026-115917, GHSA-xgh8-qwjh-q853 and related
LiteLLM proxy|4000|/health/readiness|1.84.0|CVE-2026-49468, CVE-2026-59822 and related"

# LiteLLM releases published to PyPI with credential-stealing malware: 1.82.7 and
# 1.82.8 (March 2026, PYSEC-2026-2) and 1.107.0 (October 21, 2026, also pushed as
# the v1.107.0 Docker images). Exact matches only; 1.107.0rc1 and rc2 were not
# affected by this compromise.
LITELLM_COMPROMISED_RELEASES="1.82.7 1.82.8 1.107.0"
LITELLM_COMPROMISED_IMAGE_TAGS="v1.107.0"
# 1.106.9 fixes GHSA-2rwg-2wh4-7c4f and includes the GHSA-w4c7-34wj-hqm8 fix.
LITELLM_RECOVERY_GUIDANCE="a verified patched release (1.106.9 or later on the 1.106 branch)"

# Print "version<TAB>X.Y.Z<TAB>exact|suffixed|prerelease<TAB>shown", "unparsed",
# "absent" (LiteLLM readiness without a version field) or "other" from a bounded
# response. A pre-release (SemVer "-rc1", PEP 440 "rc1", "a2", ".dev3") comes
# before its X.Y.Z; "+local" and ".post1" do not. "shown" adds only a short,
# plain pre-release suffix to X.Y.Z. Never echo raw text.
runtime_version_metadata() {
    python3 -I -B -S -c '
import json, re, sys
service = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    version = None
    if service == "Ollama":
        if isinstance(obj, dict) and set(obj) == {"version"} and isinstance(obj["version"], str):
            version = obj["version"]
    elif service == "vLLM":
        if isinstance(obj, dict) and isinstance(obj.get("version"), str):
            version = obj["version"]
        elif isinstance(obj, str) and obj.startswith("vLLM version "):
            version = obj[len("vLLM version "):]
    elif isinstance(obj, dict) and isinstance(obj.get("status"), str):
        if isinstance(obj.get("litellm_version"), str):
            version = obj["litellm_version"]
        elif "db" in obj:
            print("absent")
            sys.exit(0)
    if version is None:
        print("other")
    else:
        match = re.match(r"v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,6})(?![0-9])", version)
        if match:
            base = ".".join(match.groups())
            suffix = version[match.end():]
            release = suffix.split("+", 1)[0]
            shown = base
            if not suffix:
                exact = "exact"
            elif release.startswith("-") or re.match(r"[._]?(a|alpha|b|beta|c|rc|pre|preview|dev)(?![a-z])", release, re.I):
                exact = "prerelease"
                shown = base + (suffix if re.fullmatch(r"[0-9A-Za-z.+_-]{1,40}", suffix) else "-pre")
            else:
                exact = "suffixed"
            print("version\t" + base + "\t" + exact + "\t" + shown)
        else:
            print("unparsed")
except (ValueError, TypeError, RecursionError):
    print("other")
' "$1" 2>/dev/null
}

# Return 0 when dotted version $1 is lower than $2.
version_below() {
    local -a have=() need=()
    local i a b
    IFS=. read -r -a have <<< "$1"
    IFS=. read -r -a need <<< "$2"
    for i in 0 1 2; do
        a=$((10#${have[i]:-0})); b=$((10#${need[i]:-0}))
        if [[ "$a" -lt "$b" ]]; then return 0; fi
        if [[ "$a" -gt "$b" ]]; then return 1; fi
    done
    return 1
}

# Return 0 when $1 is exactly one of the compromised LiteLLM releases.
litellm_release_compromised() {
    [[ " $LITELLM_COMPROMISED_RELEASES " == *" $1 "* ]]
}

# Read-only listing of common Python environments for LiteLLM package metadata
# and the files the 2026 PyPI malware drops. -S keeps this interpreter from
# loading any .pth file it inspects. Prints "ioc<TAB>path",
# "bad<TAB>version<TAB>path" or "ok<TAB>version"; paths use ~ for $HOME.
litellm_package_findings() {
    python3 -I -B -S - "$HOME" "${TMPDIR:-/tmp}" $LITELLM_COMPROMISED_RELEASES <<'PY' 2>/dev/null
import glob, os, re, sys, sysconfig
home, tmpdir, bad = sys.argv[1], sys.argv[2], set(sys.argv[3:])
system_patterns = [
    "/usr/lib/python3*/site-packages", "/usr/lib/python3*/dist-packages",
    "/usr/lib/python3/dist-packages", "/usr/local/lib/python3*/site-packages",
    "/usr/local/lib/python3*/dist-packages", "/opt/homebrew/lib/python3*/site-packages",
    "/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
    "/opt/conda/lib/python3*/site-packages", "/opt/conda/envs/*/lib/python3*/site-packages",
]
home_patterns = [
    ".local/lib/python3*/site-packages", "Library/Python/3*/lib/python/site-packages",
    ".pyenv/versions/*/lib/python3*/site-packages",
    ".pyenv/versions/*/envs/*/lib/python3*/site-packages",
    ".venv/lib/python3*/site-packages", "venv/lib/python3*/site-packages",
    "*/.venv/lib/python3*/site-packages", "*/venv/lib/python3*/site-packages",
    "*/*/.venv/lib/python3*/site-packages", "*/*/venv/lib/python3*/site-packages",
    ".virtualenvs/*/lib/python3*/site-packages",
    ".local/pipx/venvs/*/lib/python3*/site-packages",
    ".local/share/pipx/venvs/*/lib/python3*/site-packages",
    ".local/share/uv/tools/*/lib/python3*/site-packages",
]
for base in ("miniconda3", "anaconda3", "miniforge3", "mambaforge"):
    home_patterns += [base + "/lib/python3*/site-packages", base + "/envs/*/lib/python3*/site-packages"]

def shown(path):
    if home and (path == home or path.startswith(home.rstrip("/") + "/")):
        path = "~" + path[len(home.rstrip("/")):]
    return "".join(c if c.isprintable() and c != "\t" else "?" for c in path)

candidates = [sysconfig.get_paths().get(k) for k in ("purelib", "platlib")]
for pattern in system_patterns:
    candidates += sorted(glob.glob(pattern))
if home and os.path.isdir(home):
    for pattern in home_patterns:
        candidates += sorted(glob.glob(os.path.join(glob.escape(home), pattern)))

seen = set()
ok = set()
for directory in candidates:
    if not directory or not os.path.isdir(directory):
        continue
    real = os.path.realpath(directory)
    if real in seen:
        continue
    seen.add(real)
    if len(seen) > 500:
        break
    for name in ("cook.pth", "litellm_init.pth"):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name == "cook.pth":
            try:
                with open(path, "rb") as handle:
                    if handle.read(64).strip() != b"import cook":
                        continue
            except OSError:
                pass
        print("ioc\t" + shown(path))
    try:
        entries = os.listdir(directory)
    except OSError:
        continue
    for entry in entries:
        match = re.fullmatch(r"litellm-([0-9][0-9A-Za-z.+!]*?)(?:-py[0-9.]+)?\.(?:dist|egg)-info", entry)
        if not match:
            continue
        version = match.group(1)
        if version in bad:
            print("bad\t" + version + "\t" + shown(os.path.join(directory, entry)))
        else:
            ok.add(version)

for directory in sorted({"/tmp", tmpdir}):
    for name in (".pc_once_72129118c59f5636c0bb", "remote_code_loader.lock"):
        path = os.path.join(directory, name)
        if os.path.lexists(path):
            print("ioc\t" + shown(path))
for version in sorted(ok):
    print("ok\t" + version)
PY
}

# Local image tags only; no pulls, registry lookups or container access.
# Prints "bad<TAB>tag<TAB>image repository:tag".
litellm_image_findings() {
    command_exists docker || return 0
    local images ref tag
    images=$(docker_read_metadata images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null) || return 0
    while IFS= read -r ref; do
        # Tag styles: v1.2.3, main-v1.2.3, v1.2.3-stable, main-v1.2.3-nightly.
        # Release candidates (v1.2.3rc1, v1.2.3-rc1, main-v1.2.3.rc1) never match.
        [[ "$ref" =~ (^|/)(berriai/litellm(-database|-non_root)?|litellm/litellm):([A-Za-z0-9_.]+-)?(v[0-9]+\.[0-9]+\.[0-9]+)(-[A-Za-z0-9_.-]+)?$ ]] || continue
        tag="${BASH_REMATCH[5]}"
        case "${BASH_REMATCH[6]}" in
            -[Rr][Cc]*|-[Aa][Ll][Pp][Hh][Aa]*|-[Bb][Ee][Tt][Aa]*|-[Dd][Ee][Vv]*|-[Pp][Rr][Ee]*) continue ;;
        esac
        if [[ " $LITELLM_COMPROMISED_IMAGE_TAGS " == *" $tag "* ]]; then
            printf 'bad\t%s\tdocker image %s\n' "$tag" "$ref"
        fi
    done <<< "$images"
}

check_runtime_versions() {
    section "17" "Runtime Versions"
    if ! command_exists python3; then
        result_skip "python3 is required for runtime version and LiteLLM package checks"
        return
    fi
    local probe_list="$RUNTIME_MIN_VERSIONS"
    if ! command_exists curl; then
        result_skip "curl is required for bounded runtime version probes; checking local LiteLLM packages only"
        probe_list=""
    fi

    # Scope: one read-only GET per runtime on its default port. Identity is
    # confirmed from the response shape or the listening process before a
    # version is trusted. No inference, credentials, redirects or proxies.
    local service port route minimum advisories lines line host target exposed bind_known
    local process_identity response status body metadata state version exact shown identified label
    local results_before=$TOTAL_CHECKS
    while IFS='|' read -r service port route minimum advisories; do
        [[ -n "$service" ]] || continue
        bind_known=true; exposed=false; process_identity=false; target=""
        if lines=$(get_listen_line "$port"); then
            [[ -n "$lines" ]] || continue
        else
            bind_known=false; lines=""
        fi
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            host=$(get_listen_host "$line" "$port")
            case "$host" in
                '0.0.0.0'|'*') exposed=true; target="127.0.0.1" ;;
                '::') exposed=true; [[ -n "$target" ]] || target="::1" ;;
                *)
                    if is_loopback_host "$host"; then
                        target="$host"
                    else
                        exposed=true
                        # Literal addresses only; never probe a discovered hostname.
                        if [[ -z "$target" ]] && is_numeric_ip_host "$host"; then
                            target="$host"
                        fi
                    fi ;;
            esac
            case "$service:$line" in
                Ollama:*'"ollama"'*|vLLM:*'"vllm"'*|"LiteLLM proxy:"*'"litellm"'*) process_identity=true ;;
            esac
        done <<< "$lines"
        if [[ -z "$target" ]]; then
            if [[ "$bind_known" == true ]]; then
                result_skip "${service} port ${port}: unsupported local bind address; version not checked"
                continue
            fi
            target="127.0.0.1"
        fi

        response=$(curl -q -s --connect-timeout 2 --max-time 5 --max-filesize 65536 --noproxy '*' --proto '=http' -w '\n%{http_code}' "http://$(format_http_host "$target"):${port}${route}" 2>/dev/null) || response=$'\n000'
        status="${response##*$'\n'}"
        body="${response%$'\n'*}"
        metadata="other"
        if [[ "$status" == "200" && "${#body}" -le 65536 ]]; then
            metadata=$(printf '%s' "$body" | runtime_version_metadata "$service")
        fi
        state="" version="" exact="" shown=""
        IFS=$'\t' read -r state version exact shown <<< "$metadata" || true

        # Ollama's and LiteLLM's version payloads are distinctive. vLLM's /version
        # shape is generic, so it also needs the process or the model-list owner.
        identified="$process_identity"
        case "$service" in
            Ollama) [[ "$state" == version || "$state" == unparsed ]] && identified=true ;;
            "LiteLLM proxy") [[ "$state" == version || "$state" == unparsed ]] && identified=true ;;
            vLLM)
                if [[ "$identified" == false && ( "$state" == version || "$state" == unparsed ) ]]; then
                    local models_response
                    models_response=$(curl -q -s --connect-timeout 2 --max-time 5 --max-filesize 65536 --noproxy '*' --proto '=http' -w '\n%{http_code}' "http://$(format_http_host "$target"):${port}/v1/models" 2>/dev/null) || models_response=$'\n000'
                    if [[ "${models_response##*$'\n'}" == "200" ]] && [[ "$(printf '%s' "${models_response%$'\n'*}" | api_model_metadata vLLM)" == vLLM ]]; then
                        identified=true
                    fi
                fi ;;
        esac
        if [[ "$identified" == false ]]; then
            if [[ "$status" != "000" ]]; then
                result_skip "${service} port ${port}${route}: service identity unconfirmed; version not checked"
            fi
            continue
        fi

        label="${service} on port ${port}"
        case "$state" in
            version)
                if [[ "$service" == "LiteLLM proxy" && "$exact" == exact ]] && litellm_release_compromised "$version"; then
                    result_cooked "${label} reports ${version}, a release published with credential-stealing malware; treat the host as compromised, rotate its provider keys and master key, and redeploy ${LITELLM_RECOVERY_GUIDANCE}" "Rotate all exposed keys immediately and redeploy ${LITELLM_RECOVERY_GUIDANCE}"
                elif [[ "$service" == Ollama && "$version" == "0.0.0" ]]; then
                    result_unknown "${label} reports development build 0.0.0; confirm it includes fixes for ${advisories}" "Verify Ollama commit includes fixes for ${advisories}"
                elif version_below "$version" "$minimum" || { [[ "$exact" == prerelease ]] && ! version_below "$minimum" "$version"; }; then
                    if [[ "$bind_known" == false ]]; then
                        result_warming "${label} reports ${shown}, older than ${minimum} (${advisories}); bind exposure not verified" "Upgrade ${service} to ${minimum} or later"
                    elif [[ "$exposed" == true ]]; then
                        result_cooked "${label} reports ${shown}, older than ${minimum} (${advisories}), and listens beyond localhost" "Upgrade ${service} to ${minimum} or later and bind to 127.0.0.1"
                    else
                        result_warming "${label} reports ${shown}, older than ${minimum} (${advisories}); bound to localhost" "Upgrade ${service} to ${minimum} or later"
                    fi
                else
                    result_safe "${label} reports ${shown}, at or above ${minimum} (advisories reviewed ${RUNTIME_VERSIONS_REVIEWED})"
                fi ;;
            absent)
                result_skip "${label} does not publish its version on ${route}; check the deployed version against LiteLLM security advisories and rule out ${LITELLM_COMPROMISED_RELEASES// /, }" ;;
            unparsed)
                result_unknown "${label}: version string not recognized; confirm ${minimum} or later (${advisories})" "Verify ${service} version manually; see https://iscooked.com/unknowns#runtime" ;;
            *)
                result_unknown "${label}: version unavailable (HTTP ${status}); confirm ${minimum} or later (${advisories})" "Verify ${service} version manually; see https://iscooked.com/unknowns#runtime" ;;
        esac
    done <<< "$probe_list"

    # A malicious pip install is invisible from the network, so also look for
    # the packages and dropped files on disk, plus locally pulled image tags.
    local findings kind detail where ioc_count=0 bad_count=0 first_ioc="" first_bad="" ok_versions=""
    findings="$(litellm_package_findings || true)"$'\n'"$(litellm_image_findings || true)"
    while IFS=$'\t' read -r kind detail where; do
        case "$kind" in
            ioc) ioc_count=$((ioc_count + 1)); [[ -n "$first_ioc" ]] || first_ioc="$detail" ;;
            bad) bad_count=$((bad_count + 1)); [[ -n "$first_bad" ]] || first_bad="${detail} in ${where}" ;;
            ok) ok_versions="${ok_versions:+$ok_versions, }$detail" ;;
        esac
    done <<< "$findings"
    if [[ "$ioc_count" -gt 0 ]]; then
        result_cooked "LiteLLM supply-chain malware file found: ${first_ioc}$( [[ "$ioc_count" -le 1 ]] || printf ' (+%s more)' "$((ioc_count - 1))" ); treat this machine as compromised, stop the loader, remove the files, reinstall ${LITELLM_RECOVERY_GUIDANCE} and rotate every credential it could reach" "Remove dropped malware files, rotate all credentials, and reinstall ${LITELLM_RECOVERY_GUIDANCE}"
    fi
    if [[ "$bad_count" -gt 0 ]]; then
        result_cooked "Compromised LiteLLM release ${first_bad}$( [[ "$bad_count" -le 1 ]] || printf ' (+%s more)' "$((bad_count - 1))" ): published with credential-stealing malware; reinstall ${LITELLM_RECOVERY_GUIDANCE} and rotate every credential this machine could reach" "Reinstall ${LITELLM_RECOVERY_GUIDANCE} and rotate all credentials on this host"
    fi
    if [[ "$ioc_count" -eq 0 && "$bad_count" -eq 0 && -n "$ok_versions" ]]; then
        result_safe "LiteLLM ${ok_versions} found in common Python environments; not a compromised release (${LITELLM_COMPROMISED_RELEASES// /, })"
    fi

    if [[ "$TOTAL_CHECKS" -eq "$results_before" ]]; then
        result_skip "No Ollama, vLLM or LiteLLM proxy on its default port and no LiteLLM package in common Python environments; nothing to check"
    fi
}

check_ollama_config() {
    section "12" "Ollama-Specific Checks"

    if ! command_exists ollama; then
        result_skip "Ollama not installed"
        return
    fi

    # These values belong to this scanner, not necessarily the running service.
    local ollama_host="${OLLAMA_HOST:-}" bind_host
    if [[ -n "$ollama_host" ]]; then
        bind_host="${ollama_host#*://}"
        bind_host="${bind_host%%/*}"
        if [[ "$ollama_host" == *'@'* || "$ollama_host" == *'?'* || "$ollama_host" == *'#'* ]]; then
            result_unknown "OLLAMA_HOST has an unsupported URL form in the scanner environment; verify running service settings"
        else
            case "$bind_host" in
                '['*']'*) bind_host="${bind_host%%]*}"; bind_host="${bind_host#[}" ;;
                ::|::1) ;;
                *) bind_host="${bind_host%%:*}" ;;
            esac
            case "$bind_host" in
                0.0.0.0|::)
                    result_cooked "OLLAMA_HOST selects all interfaces in the scanner environment; verify running service settings" "Set OLLAMA_HOST=127.0.0.1:11434 to bind Ollama to localhost" ;;
                127.0.0.1|localhost|::1)
                    result_safe "OLLAMA_HOST selects loopback in the scanner environment; running service settings are not verified" ;;
                *)
                    result_unknown "OLLAMA_HOST requires address resolution in the scanner environment; verify the intended bind and running service settings" "Use an explicit IP such as 127.0.0.1:11434; see https://iscooked.com/unknowns#runtime" ;;
            esac
        fi
    else
        result_skip "OLLAMA_HOST is absent from the scanner environment; running service settings are not verified"
    fi

    # Check OLLAMA_ORIGINS
    local ollama_origins="${OLLAMA_ORIGINS:-}"
    if [[ "$ollama_origins" == "*" ]]; then
        result_cooked "OLLAMA_ORIGINS=* in the scanner environment permits any origin; verify running service settings" "Restrict OLLAMA_ORIGINS to explicit trusted origins instead of *"
    elif [[ -n "$ollama_origins" ]]; then
        result_warming "OLLAMA_ORIGINS is set in the scanner environment; review permitted origins and running service settings" "Keep OLLAMA_ORIGINS limited to trusted local origins"
    fi

    # Check systemd service file (Linux only)
    if [[ "$OS_TYPE" == "linux" && -f /etc/systemd/system/ollama.service ]]; then
        local svc_user
        if ! svc_user=$(awk -F= '/^[[:space:]]*User[[:space:]]*=/ { value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value) } END { print value }' /etc/systemd/system/ollama.service 2>/dev/null); then
            result_unknown "Ollama systemd service file is unreadable; effective service user is unknown" "Inspect /etc/systemd/system/ollama.service with sudo; see https://iscooked.com/unknowns#runtime"
        elif [[ "$svc_user" == "root" || -z "$svc_user" ]]; then
            result_warming "Ollama systemd service file selects root or omits User=; overrides and the active user are not verified" "Set User=ollama in /etc/systemd/system/ollama.service"
        else
            result_safe "Ollama systemd service file selects a non-root user; overrides and the active user are not verified"
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

# ─── Score, Diff & Summary ──────────────────────────────────────────────────────

validate_diff_file() {
    local diff_path="$1"
    python3 -I -B -S - "$diff_path" <<'DIFF_VAL_PY'
import json
import os
import stat
import sys

path = sys.argv[1]
LIMIT = 10485760
try:
    s = os.stat(path)
    if not stat.S_ISREG(s.st_mode) or s.st_size > LIMIT:
        raise ValueError("Diff baseline must be a regular JSON file under 10 MiB.")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Diff baseline exceeds 10 MiB.")
    obj = json.loads(raw.decode("utf-8"))
    if (not isinstance(obj, dict)
            or obj.get("schema_version") != 1
            or not isinstance(obj.get("findings"), list)
            or not isinstance(obj.get("summary", {}).get("score", {}).get("value"), int)):
        raise ValueError("Diff baseline is not a valid iscooked schema_version 1 JSON report.")
except (OSError, ValueError, UnicodeDecodeError, TypeError) as exc:
    print(f"Invalid --diff file: {exc}", file=sys.stderr)
    sys.exit(2)
DIFF_VAL_PY
}

compute_diff_json() {
    local displayed_score="$SCORE"
    [[ "$displayed_score" -le 100 ]] || displayed_score=100
    local index
    {
        for ((index=0; index<TOTAL_CHECKS; index++)); do
            printf '%s\0' "${FINDING_CHECK_IDS[index]}" "${FINDING_CHECK_TITLES[index]}" \
                "${FINDING_STATUSES[index]}" "${FINDING_MESSAGES[index]}"
        done
    } | python3 -I -B -S -c '
from collections import Counter
import json
import os
import re
import sys

def clean(text):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(text))

diff_path = sys.argv[1]
curr_score = int(sys.argv[2])
LIMIT = 10485760
fd = os.open(diff_path, os.O_RDONLY | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as stream:
    prev = json.loads(stream.read(LIMIT).decode("utf-8"))

prev_score = int(prev["summary"]["score"]["value"])
PROBLEM_STATES = {"critical", "warning", "unknown"}

prev_counts = Counter()
prev_meta = {}
for item in prev.get("findings", []):
    if not isinstance(item, dict):
        continue
    st = str(item.get("status", ""))
    if st not in PROBLEM_STATES:
        continue
    chk = item.get("check", {})
    cid = clean(chk.get("id", ""))
    title = clean(chk.get("title", ""))
    msg = clean(item.get("message", ""))
    key = (cid, st, msg)
    prev_counts[key] += 1
    prev_meta.setdefault(key, {"check": {"id": cid, "title": title}, "status": st, "message": msg})

fields = sys.stdin.buffer.read().decode("utf-8", errors="replace").split("\0")
fields.pop()
curr_counts = Counter()
curr_meta = {}
for start in range(0, len(fields), 4):
    cid, title, st, msg = fields[start:start + 4]
    if st not in PROBLEM_STATES:
        continue
    key = (cid, st, msg)
    curr_counts[key] += 1
    curr_meta.setdefault(key, {"check": {"id": cid, "title": title}, "status": st, "message": msg})

resolved = []
for key, count in (prev_counts - curr_counts).items():
    for _ in range(count):
        resolved.append(prev_meta[key])

new = []
for key, count in (curr_counts - prev_counts).items():
    for _ in range(count):
        new.append(curr_meta[key])

print(json.dumps({
    "previous_score": prev_score,
    "current_score": curr_score,
    "score_delta": curr_score - prev_score,
    "resolved_count": len(resolved),
    "new_count": len(new),
    "resolved": resolved,
    "new": new,
}, ensure_ascii=True))
' "$DIFF_FILE" "$displayed_score"
}

print_diff_text() {
    [[ -n "$DIFF_JSON" ]] || return 0
    local tag body
    echo -e "  ${WHITE}${BOLD}DIFF VS PREVIOUS SCAN${RESET}"
    while IFS=$'\t' read -r tag body; do
        case "$tag" in
            score) echo -e "  ${DIM}${body}${RESET}" ;;
            resolved_hdr) echo -e "  ${GREEN}${BOLD}${body}${RESET}" ;;
            resolved) echo -e "    ${GREEN}- ${body}${RESET}" ;;
            new_hdr) echo -e "  ${RED}${BOLD}${body}${RESET}" ;;
            new) echo -e "    ${RED}+ ${body}${RESET}" ;;
            none) echo -e "    ${DIM}${body}${RESET}" ;;
        esac
    done < <(printf '%s' "$DIFF_JSON" | python3 -I -B -S -c '
import json, sys
d = json.load(sys.stdin)
prev_s = d["previous_score"]
curr_s = d["current_score"]
delta = d["score_delta"]
res_count = d["resolved_count"]
new_count = d["new_count"]
sign = "+" if delta > 0 else ""
print(f"score\tScore change: {sign}{delta} points ({prev_s}% -> {curr_s}%)")
print(f"resolved_hdr\tResolved ({res_count}):")
if d["resolved"]:
    for item in d["resolved"]:
        cid = item["check"]["id"]
        st = item["status"]
        msg = item["message"]
        print(f"resolved\t[{cid}] {st}: {msg}")
else:
    print("none\t(none)")
print(f"new_hdr\tNew ({new_count}):")
if d["new"]:
    for item in d["new"]:
        cid = item["check"]["id"]
        st = item["status"]
        msg = item["message"]
        print(f"new\t[{cid}] {st}: {msg}")
else:
    print("none\t(none)")
')
    echo ""
}

summary_status() {
    if [[ "$COOKED_COUNT" -gt 0 ]]; then
        printf critical
    elif [[ "$WARMING_COUNT" -gt 0 ]]; then
        printf warning
    elif [[ "$UNKNOWN_COUNT" -gt 0 || "$SKIPPED_COUNT" -gt 0 || "$TOTAL_CHECKS" -eq 0 ]]; then
        printf inconclusive
    else
        printf no_findings
    fi
}

print_summary() {
    local displayed_score=$SCORE
    [[ "$displayed_score" -le 100 ]] || displayed_score=100

    local level_text level_color bar_char
    if [[ "$displayed_score" -ge 70 ]]; then
        level_text="FULLY COOKED"
        level_color="$RED"
        bar_char="█"
    elif [[ "$displayed_score" -ge 40 ]]; then
        level_text="MEDIUM RARE"
        level_color="$YELLOW"
        bar_char="▓"
    elif [[ "$displayed_score" -ge 15 ]]; then
        level_text="SLIGHTLY WARM"
        level_color="$CYAN"
        bar_char="▒"
    else
        level_text="LOOKING FRESH"
        level_color="$GREEN"
        bar_char="░"
    fi

    if [[ $((COOKED_COUNT + WARMING_COUNT + SAFE_COUNT)) -eq 0 ]]; then
        level_text="STILL DEFROSTING"
        level_color="$CYAN"
        bar_char="░"
    elif [[ "$displayed_score" -lt 15 && $((COOKED_COUNT + WARMING_COUNT)) -gt 0 ]]; then
        level_text="SLIGHTLY WARM"
        level_color="$CYAN"
        bar_char="▒"
    fi
    [[ "$COOKED_COUNT" -eq 0 ]] || level_color="$RED"

    local bar_width=40
    local filled=$((displayed_score * bar_width / 100))
    local bar="" i
    for ((i=0; i<bar_width; i++)); do
        if [[ "$i" -lt "$filled" ]]; then bar+="$bar_char"; else bar+=" "; fi
    done

    echo ""
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
    echo -e "  ${WHITE}${BOLD}YOUR COOKED SCORE${RESET}"
    echo ""
    echo -e "  ${level_color}${BOLD}${displayed_score}%${RESET} ${DIM}cooked${RESET}  [${level_color}${bar}${RESET}]"
    echo ""
    echo -e "  ${level_color}${BOLD}${level_text}${RESET}"
    echo ""
    echo -e "  ${RED}${BOLD}${COOKED_COUNT}${RESET} critical  ${YELLOW}${BOLD}${WARMING_COUNT}${RESET} warnings  ${GREEN}${BOLD}${SAFE_COUNT}${RESET} passed"
    echo -e "  ${CYAN}${UNKNOWN_COUNT}${RESET} unknown  ${DIM}${SKIPPED_COUNT} skipped  (${TOTAL_CHECKS} results)${RESET}"
    echo ""
    case "$(summary_status)" in
        critical) echo -e "  ${RED}Fix critical findings first.${RESET}" ;;
        warning) echo -e "  ${YELLOW}Turn down the heat. Check the warnings above.${RESET}" ;;
        inconclusive) echo -e "  ${CYAN}Some checks are still on ice. Check unknowns and skips.${RESET}" ;;
        no_findings) echo -e "  ${GREEN}No heat from the checks that ran.${RESET}" ;;
    esac
    echo ""
    print_diff_text
}

print_json_report() {
    # NUL separates fields. The serializer handles quotes and invalid UTF-8.
    local index areas_with_observations areas_with_unknown areas_with_skips
    areas_with_observations=$(coverage_count observations)
    areas_with_unknown=$(coverage_count unknown)
    areas_with_skips=$(coverage_count skips)
    {
        for ((index=0; index<TOTAL_CHECKS; index++)); do
            printf '%s\0' "${FINDING_CHECK_IDS[index]}" "${FINDING_CHECK_TITLES[index]}" \
                "${FINDING_STATUSES[index]}" "${FINDING_MESSAGES[index]}" "${FINDING_POINTS[index]}" \
                "${FINDING_HINTS[index]}"
        done
    } | python3 -I -B -S -c '
import json
import sys

version, platform, status = sys.argv[1:4]
(total, critical, warning, passed, unknown, skipped, score,
 areas_started, areas_observations, areas_unknown, areas_skips) = map(int, sys.argv[4:15])
problems_only, diff_raw = sys.argv[15:17]
fields = sys.stdin.buffer.read().decode("utf-8", errors="replace").split("\0")
fields.pop()
if len(fields) != total * 6:
    raise SystemExit("Incomplete report records")
findings = []
for start in range(0, len(fields), 6):
    check_id, title, state, message, points, hint = fields[start:start + 6]
    if problems_only == "true" and state not in ("critical", "warning", "unknown"):
        continue
    item = {"check": {"id": check_id, "title": title},
            "status": state, "message": message, "points": int(points)}
    if hint:
        item["remediation"] = hint
    findings.append(item)
report = {"schema_version": 1, "scanner": {"name": "iscooked", "version": version},
          "platform": platform, "completed": True,
          "summary": {"status": status,
                      "counts": {"total": total, "critical": critical, "warning": warning,
                                 "passed": passed, "unknown": unknown, "skipped": skipped},
                      "score": {"value": min(score, 100), "raw_value": score, "maximum": 100,
                                "kind": "heuristic", "includes_unknown": False}},
          "coverage": {"areas_started": areas_started,
                       "areas_with_observations": areas_observations,
                       "areas_with_unknown": areas_unknown,
                       "areas_with_skips": areas_skips},
          "findings": findings}
if diff_raw:
    report["diff"] = json.loads(diff_raw)
json.dump(report, sys.stdout, ensure_ascii=True, indent=2)
print()
' "$VERSION" "$OS_TYPE" "$(summary_status)" "$TOTAL_CHECKS" "$COOKED_COUNT" \
        "$WARMING_COUNT" "$SAFE_COUNT" "$UNKNOWN_COUNT" "$SKIPPED_COUNT" "$SCORE" \
        "$STARTED_AREA_COUNT" "$areas_with_observations" "$areas_with_unknown" "$areas_with_skips" \
        "$PROBLEMS_ONLY" "$DIFF_JSON"
}

usage() {
    cat <<'USAGE'
Usage: bash iscooked.com [options]

Examine coding agent and local AI setups. Local-only, read-only, zero telemetry.

  -h, --help          Show this help without a scan.
  --version           Show the scanner version without a scan.
  --json              Write one JSON report (requires Python 3).
  --no-color          Disable terminal colors.
  -q, --problems-only Show only critical, warning, and unknown findings in output.
  --only CHECKS       Run only comma-separated check IDs or names (e.g. 01,mcp,agents,versions).
  --skip CHECKS       Skip comma-separated check IDs or names.
  --diff FILE         Compare findings and score against a prior --json report (requires Python 3).
  --fail-on LEVEL     Return 1 for the selected findings:
                      critical: critical findings
                      warning:  critical findings or warnings
                      unknown:  critical findings, warnings, or unknown results

Without --fail-on, a completed scan returns 0 regardless of its findings.
Invalid options or unsupported requirements return 2 before the scan.
Skipped results do not trigger --fail-on. A successful exit does not prove safety.
Elevated privileges can improve some firewall and port checks.
USAGE
}

configure_output() {
    local color
    if [[ "$COLOR_MODE" == never || ! -t 1 || -n "${NO_COLOR:-}" || "${TERM:-}" == dumb ]]; then
        for color in RED GREEN YELLOW BLUE MAGENTA CYAN WHITE DIM BOLD RESET; do
            printf -v "$color" '%s' ''
        done
        COOKED="🔥 COOKED"
        WARMING="⚠  WARMING UP"
        SAFE="✅ SAFE"
        UNKNOWN="❓ UNKNOWN"
    fi
}

check_bash_version() {
    local major="${1:-${BASH_VERSINFO[0]}}" minor="${2:-${BASH_VERSINFO[1]}}"
    if [[ "$major" -lt 3 || ( "$major" -eq 3 && "$minor" -lt 2 ) ]]; then
        printf '%s\n' 'Bash 3.2 or later is required. Select that Bash executable to run this file.' >&2
        return 2
    fi
    return 0
}

exit_for_findings() {
    case "$FAIL_ON" in
        critical) [[ "$COOKED_COUNT" -eq 0 ]] ;;
        warning) [[ $((COOKED_COUNT + WARMING_COUNT)) -eq 0 ]] ;;
        unknown) [[ $((COOKED_COUNT + WARMING_COUNT + UNKNOWN_COUNT)) -eq 0 ]] ;;
        none) return 0 ;;
    esac
}

# ─── Main ───────────────────────────────────────────────────────────────────────

main() {
    local information="" required_tool
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) information=help ;;
            --version) information=version ;;
            --json) OUTPUT_FORMAT=json ;;
            --no-color) COLOR_MODE=never ;;
            -q|--problems-only) PROBLEMS_ONLY=true ;;
            --only)
                if [[ $# -lt 2 ]]; then
                    printf '%s\n' 'Missing --only check list. Use --help.' >&2
                    return 2
                fi
                shift
                ONLY_CHECKS=$(parse_check_list "$1") || {
                    printf '%s\n' 'Invalid --only check selector. Use --help.' >&2
                    return 2
                } ;;
            --skip)
                if [[ $# -lt 2 ]]; then
                    printf '%s\n' 'Missing --skip check list. Use --help.' >&2
                    return 2
                fi
                shift
                SKIP_CHECKS=$(parse_check_list "$1") || {
                    printf '%s\n' 'Invalid --skip check selector. Use --help.' >&2
                    return 2
                } ;;
            --diff)
                if [[ $# -lt 2 ]]; then
                    printf '%s\n' 'Missing --diff baseline JSON file. Use --help.' >&2
                    return 2
                fi
                shift
                DIFF_FILE="$1" ;;
            --fail-on)
                if [[ $# -lt 2 ]]; then
                    printf '%s\n' 'Missing --fail-on level. Use --help.' >&2
                    return 2
                fi
                shift
                case "$1" in
                    critical|warning|unknown) FAIL_ON="$1" ;;
                    *) printf '%s\n' 'Invalid --fail-on level. Use --help.' >&2; return 2 ;;
                esac ;;
            *) printf '%s\n' 'Unknown argument. Use --help.' >&2; return 2 ;;
        esac
        shift
    done
    case "$information" in
        help) usage; return 0 ;;
        version) printf 'iscooked %s\n' "$VERSION"; return 0 ;;
    esac
    check_bash_version "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" || return 2
    if [[ "$OS_TYPE" != linux && "$OS_TYPE" != macos ]]; then
        printf '%s\n' 'This scanner supports Linux and macOS only.' >&2
        return 2
    fi
    if [[ "${HOME:-}" != /* || ! -d "${HOME:-}" ]]; then
        printf '%s\n' 'HOME must identify an existing absolute directory for local file checks.' >&2
        return 2
    fi
    for required_tool in awk basename cat find grep ps stat tr uname wc whoami; do
        if ! command_exists "$required_tool"; then
            printf 'Required system tool is unavailable: %s\n' "$required_tool" >&2
            return 2
        fi
    done
    if [[ "$OUTPUT_FORMAT" == json ]] && ! command_exists python3; then
        printf '%s\n' 'JSON output requires python3. Use text output or install Python 3.' >&2
        return 2
    fi
    if [[ -n "$DIFF_FILE" ]]; then
        if ! command_exists python3; then
            printf '%s\n' '--diff requires python3. Install Python 3 or omit --diff.' >&2
            return 2
        fi
        validate_diff_file "$DIFF_FILE" || return 2
    fi
    configure_output
    FULL_SCAN=true
    if [[ "$OUTPUT_FORMAT" == text ]]; then
        banner
    fi

    run_check check_network_exposure
    run_check check_api_auth
    run_check check_model_permissions
    run_check check_docker_risks
    run_check check_gpu_exposure
    run_check check_telemetry
    run_check check_firewall
    run_check check_ssl_tls
    run_check check_processes
    run_check check_sensitive_files
    run_check check_history_logs
    run_check check_ollama_config
    run_check check_browser_debugging
    run_check check_mcp_config
    run_check check_agent_gateway
    run_check check_model_code_execution
    run_check check_runtime_versions

    if [[ -n "$DIFF_FILE" ]]; then
        DIFF_JSON=$(compute_diff_json)
    fi

    if [[ "$OUTPUT_FORMAT" == json ]]; then
        print_json_report
    else
        print_summary
    fi
    exit_for_findings
}

main "$@"
