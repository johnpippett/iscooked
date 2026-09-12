#!/usr/bin/env bash
# iscooked.com — Am I Cooked? Local AI Security Scanner
# https://iscooked.com | MIT License
#
# Scans your local AI setup for security and privacy risks.
# Runs locally. Sends nothing anywhere. Ever.

set -euo pipefail

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

VERSION="1.1.0"

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

result_unknown() {
    # Inspection could not be completed — explicitly report the gap instead of
    # silently treating it as SAFE. Counted like a warning so the summary shows it.
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    WARMING_COUNT=$((WARMING_COUNT + 1))
    SCORE=$((SCORE + 4))
    printf '%b  %s\n' "  ${UNKNOWN}" "$(sanitize_result_message "$1")"
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
                result_cooked "Unidentified service on port ${port} (commonly ${name}) is listening on ALL interfaces"
            elif is_bound_loopback_only "$listen_line" "$port"; then
                result_safe "Unidentified service on port ${port} (commonly ${name}) is bound to localhost only"
            else
                local bind_host
                bind_host=$(get_non_loopback_listen_host "$listen_line" "$port" || echo "non-loopback interface")
                result_warming "Unidentified service on port ${port} (commonly ${name}) is bound to non-loopback interface ${bind_host}"
            fi
        fi
    done <<< "$ai_ports"

    if [[ "$found_any" == "false" ]]; then
        result_safe "No common AI service ports detected as listening"
    fi
}

# Parse bounded model metadata without printing model names or other response data.
api_model_metadata() {
    python3 -c '
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
    for port in 11434 1234 8000; do
        case "$port" in
            11434) expected="Ollama"; route="/api/tags" ;;
            1234) expected="LM Studio"; route="/v1/models" ;;
            8000) expected="vLLM"; route="/v1/models" ;;
        esac
        lines=$(get_listen_line "$port")
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
                if [[ "$host" != "*" ]] && ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$host" 2>/dev/null; then
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
                        result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (unexpected model-list response)"
                    elif [[ "$exposed" == "true" ]]; then
                        result_cooked "${identity} ${route} on port ${port} accessible without authentication on a non-loopback interface; correlate with network exposure (same endpoint)"
                    else
                        result_warming "${identity} ${route} on port ${port} accessible without authentication on localhost; other routes were not tested"
                    fi ;;
                401) result_safe "${identity} ${route} on port ${port} requires authentication (HTTP 401); other routes were not tested" ;;
                403) result_safe "${identity} ${route} on port ${port} denied access (HTTP 403); other routes were not tested" ;;
                3??) result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (HTTP ${status} redirect, not followed)" ;;
                *) result_unknown "${identity} ${route} on port ${port}: authentication inconclusive (HTTP ${status}; unreachable, failed, or unsupported endpoint)" ;;
            esac
        done <<< "$lines"
    done
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
                    result_warming "Model directory ${dir} is world-readable (${wr_count} files)"
                elif [[ ! -r "$dir" || ! -x "$dir" ]]; then
                    result_skip "Model directory ${dir} is not readable — inspection incomplete, permissions unknown"
                else
                    result_safe "Model directory ${dir} has restrictive permissions"
                fi
            else
                result_skip "Model directory ${dir} — inspection incomplete, permissions unknown"
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

# Metadata only: no exec, socket requests, container writes, or environment reads.
docker_read_metadata() {
    if command_exists timeout; then
        timeout 5 docker "$@"
    elif command_exists gtimeout; then
        gtimeout 5 docker "$@"
    elif command_exists python3; then
        python3 -c 'import subprocess, sys
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
    if ! security_options=$(docker_read_metadata info --format '{{json .SecurityOptions}}' 2>/dev/null); then
        result_unknown "Docker daemon inspection incomplete — UNKNOWN (unreachable or bounded command unavailable)"
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
        daemon_mode=$(printf '%s' "$security_options" | python3 -c 'import json, sys
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
            result_cooked "Container '${cname}' is running as root"
        else
            result_safe "Container '${cname}' is running as user '${user}'"
        fi

        userns_mode=$(docker_read_metadata inspect --format '{{.HostConfig.UsernsMode}}' "$cname" 2>/dev/null || echo "unknown")

        # Check privileged mode
        local privileged
        if ! privileged=$(docker_read_metadata inspect --format '{{.HostConfig.Privileged}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' privileged status UNKNOWN (inspection incomplete)"
        fi
        if [[ "$privileged" == "true" ]]; then
            result_cooked "Container '${cname}' is running in PRIVILEGED mode"
        fi

        # Check host network
        local network
        if ! network=$(docker_read_metadata inspect --format '{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null); then
            result_unknown "Container '${cname}' network mode UNKNOWN (inspection incomplete)"
        fi
        if [[ "$network" == "host" ]]; then
            result_warming "Container '${cname}' is using host networking"
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
            for candidate_index in "${!mount_sources[@]}"; do
                if [[ "${mount_sources[candidate_index]}" == "$source" ]]; then
                    mount_index=$candidate_index
                    break
                fi
            done
            if [[ "$finding_level" -gt "${mount_levels[mount_index]:-0}" ]]; then
                mount_sources[mount_index]=$source
                mount_levels[mount_index]=$finding_level
                mount_messages[mount_index]=$finding_message
            fi
        done <<< "$mounts"
        for mount_index in "${!mount_sources[@]}"; do
            case "${mount_levels[mount_index]}" in
                4) result_cooked "${mount_messages[mount_index]}" ;;
                3) result_warming "${mount_messages[mount_index]}" ;;
                2)
                    if [[ "$sensitive_reported" == false ]]; then
                        result_warming "Container '${cname}' has sensitive host paths mounted"
                        sensitive_reported=true
                    fi
                    ;;
                1) result_unknown "${mount_messages[mount_index]}" ;;
            esac
        done

    done <<< "$ai_containers"
}

# Browser control inspection uses process evidence, never a guessed default port.
# Only /json/version is read; response-supplied control URLs are never followed.
browser_debugging_evidence() {
    python3 - "$OS_TYPE" <<'PY'
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
            cooked) result_cooked "$message" ;;
            safe) result_safe "$message" ;;
            unknown) result_unknown "$message" ;;
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

check_mcp_config() {
    section "14" "MCP Configuration"
    if ! command -v python3 >/dev/null 2>&1; then
        result_skip "MCP configuration inspection requires optional python3"
        return
    fi
    local mcp_output mcp_severity mcp_message
    if ! mcp_output=$(python3 - 2>/dev/null <<'MCP_PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

LIMIT = 1048576
home = Path.home()
cwd = Path.cwd()
paths = [
    (home / '.config/Claude/claude_desktop_config.json', 'Claude Desktop Linux'),
    (home / 'Library/Application Support/Claude/claude_desktop_config.json', 'Claude Desktop macOS'),
    (cwd / '.mcp.json', 'Claude Code project'),
    (home / '.claude.json', 'Claude Code user'),
    (home / '.cursor/mcp.json', 'Cursor user'),
    (cwd / '.cursor/mcp.json', 'Cursor project'),
]

def emit(level, message):
    print(level + '\t' + message)

def traversable(parents, gid=None):
    # Model a non-owner account in this group, or an unrelated local account.
    return all(s.st_mode & (stat.S_IXGRP if gid == s.st_gid else stat.S_IXOTH)
               for s in parents)

def permissions(path, label, credentials):
    try:
        resolved = path.resolve(strict=True)
        s = resolved.stat()
        parents = [p.stat() for p in resolved.parents]
        # Symlink traversal and ACLs cannot be conclusively modeled by mode bits.
        original = [path, *path.parents]
        has_links = any(p.is_symlink() for p in original)
        has_acl = sys.platform == 'darwin'
        if hasattr(os, 'listxattr'):
            for p in [resolved, *resolved.parents]:
                has_acl |= any('acl' in name.lower() for name in os.listxattr(p))
        if has_links or has_acl:
            emit('unknown', label + ': ACL or symlink access needs manual permissions review')
            return
        world = traversable(parents)
        group = traversable(parents, s.st_gid)
        # Any writable ancestor can replace its child, even if deeper paths
        # are private. Sticky directories do not allow replacing owned children.
        replace_world = any(parent.st_mode & stat.S_IWOTH
                            and not parent.st_mode & stat.S_ISVTX
                            and traversable(parents[i:])
                            for i, parent in enumerate(parents))
        replace_group = any(parent.st_mode & stat.S_IWGRP
                            and not parent.st_mode & stat.S_ISVTX
                            and traversable(parents[i:], parent.st_gid)
                            for i, parent in enumerate(parents))
        if (world and s.st_mode & stat.S_IWOTH) or replace_world:
            emit('cooked', label + ': launch configuration is world-writable or replaceable; restrict file and parent directory permissions')
        elif (group and s.st_mode & stat.S_IWGRP) or replace_group:
            emit('warming', label + ': launch configuration is group-writable or replaceable; restrict access to trusted administrators')
        if credentials:
            if world and s.st_mode & stat.S_IROTH:
                emit('cooked', label + ': credential-bearing configuration is readable by other local users; use mode 600 and a private parent directory')
            elif group and s.st_mode & stat.S_IRGRP:
                emit('warming', label + ': credential-bearing configuration is group-readable; restrict access to the intended account')
    except OSError:
        emit('unknown', label + ': effective permissions could not be inspected')

def has_credentials(server):
    # Detect key names only, and never echo either names or values.
    for field in ('env', 'headers'):
        values = server.get(field, {})
        if isinstance(values, dict):
            for key, value in values.items():
                if re.search(r'key|token|secret|password|credential|authorization', key, re.I) and value:
                    if not (isinstance(value, str) and value.startswith('${') and value.endswith('}')):
                        return True
    return False

def inspect_server(server, label):
    if not isinstance(server, dict):
        emit('unknown', label + ': unsupported server entry')
        return
    command = server.get('command', '')
    args = server.get('args', [])
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        emit('unknown', label + ': unsupported command or arguments')
        return
    # Exact known executable/package identities, not arbitrary path-looking args.
    executable = os.path.basename(command)
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
            emit('unknown', label + ': filesystem server has no explicit grants; review effective access')
            complete = False
        for grant in dict.fromkeys(grants):
            if grant.startswith('-'):
                continue
            if '$' in grant or '{' in grant:
                complete = False
                emit('unknown', label + ': filesystem grant uses unresolved variables; review resolved access')
                continue
            expanded = Path(os.path.expanduser(grant))
            if not expanded.is_absolute():
                complete = False
                emit('unknown', label + ': relative filesystem grant depends on server working directory')
                continue
            try:
                expanded = expanded.resolve()
            except (OSError, RuntimeError):
                complete = False
                emit('unknown', label + ': filesystem grant could not be resolved')
                continue
            if expanded == Path('/') or expanded == home or expanded in home.parents:
                scope = 'entire home directory' if expanded == home else 'filesystem root or ancestor of home'
                emit('warming', label + ': filesystem server grants access to ' + scope + '; narrow grants to required project directories')
                broad = True
            elif any(expanded == sensitive or sensitive in expanded.parents
                     for sensitive in (home / '.ssh', home / '.aws', home / '.gnupg', home / '.config', Path('/etc'))):
                emit('warming', label + ': filesystem server grants a sensitive directory; narrow grants to required project directories')
                broad = True
        if not broad and complete:
            emit('safe', label + ': no broad filesystem grants identified in literal arguments')
    # Known shell server identity; arbitrary shell wrappers are not inferred unsafe.
    if executable == 'mcp-server-shell' or (executable in ('npx', 'bunx') and 'mcp-server-shell' in args):
        emit('warming', label + ': known shell server configured; review command restrictions and run with minimal privileges')

found = False
seen = set()
for path, label in paths:
    if str(path) in seen:
        continue
    seen.add(str(path))
    try:
        s = path.stat()
    except FileNotFoundError:
        if path.is_symlink():
            found = True
            emit('unknown', label + ': broken config symlink')
        continue
    except OSError:
        found = True
        emit('unknown', label + ': configuration is inaccessible')
        continue
    found = True
    if not stat.S_ISREG(s.st_mode) or s.st_size > LIMIT:
        emit('unknown', label + ': unsupported file type or configuration exceeds 1 MiB limit')
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
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError()
    except (OSError, ValueError, RecursionError):
        emit('unknown', label + ': unreadable, malformed, or oversized JSON configuration')
        continue
    groups = []
    if 'mcpServers' in data:
        groups.append(data['mcpServers'])
    if label == 'Claude Code user' and isinstance(data.get('projects'), dict):
        projects = list(data['projects'].values())
        if len(projects) > 128:
            emit('unknown', label + ': project limit exceeded; inspection incomplete')
        for project in projects[:128]:
            if isinstance(project, dict) and 'mcpServers' in project:
                groups.append(project['mcpServers'])
    servers = []
    for group in groups:
        if isinstance(group, dict):
            servers.extend(group.values())
        else:
            emit('unknown', label + ': unsupported mcpServers structure')
    if not groups:
        emit('unknown', label + ': no supported mcpServers structure; unsupported formats are not evaluated')
    credentials = any(has_credentials(s) for s in servers if isinstance(s, dict))
    permissions(path, label, credentials)
    if len(servers) > 128:
        emit('unknown', label + ': server limit exceeded; inspection incomplete')
    for i, server in enumerate(servers[:128], 1):
        inspect_server(server, label + ' server ' + str(i))
    emit('skip', label + ': inspection limited to known JSON schemas, literal grants and Unix mode permissions; other clients and runtime restrictions are not evaluated')
if not found:
    emit('skip', 'No supported MCP configuration found; unsupported clients and formats are not evaluated')
MCP_PY
    ); then
        result_unknown "MCP configuration parser failed; inspection incomplete"
        return
    fi
    while IFS=$'\t' read -r mcp_severity mcp_message; do
        case "$mcp_severity" in
            cooked) result_cooked "$mcp_message" ;;
            warming) result_warming "$mcp_message" ;;
            safe) result_safe "$mcp_message" ;;
            unknown) result_unknown "$mcp_message" ;;
            skip) result_skip "$mcp_message" ;;
        esac
    done <<< "$mcp_output"
}

check_agent_gateway() {
    section "15" "Agent Gateway Configuration"
    if ! command -v python3 >/dev/null 2>&1; then
        result_skip "OpenClaw configuration inspection requires optional python3"
        return
    fi
    local gateway_output gateway_severity gateway_message
    if ! gateway_output=$(python3 - 2>/dev/null <<'GATEWAY_PY'
import fnmatch
import ipaddress
import json
import os
import stat
import sys

# Intentionally strict JSON: JSON5, includes, environment interpolation and
# runtime/CLI overrides require OpenClaw's own policy resolver and are not run.
LIMIT = 1048576

def emit(level, message):
    print(level + '\tOpenClaw: ' + message)

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

path = os.environ.get('OPENCLAW_CONFIG_PATH') or os.path.join(os.path.expanduser('~'), '.openclaw', 'openclaw.json')
try:
    before = os.lstat(path)
except FileNotFoundError:
    emit('skip', 'no configuration found')
    sys.exit(0)
except OSError:
    emit('unknown', 'configuration inaccessible; inspection incomplete')
    sys.exit(0)
try:
    if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o444 or before.st_size > LIMIT:
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError()
        raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError()
    config = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
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
        emit('unknown', 'bind requires runtime resolution; exposure with disabled auth cannot be determined')
    elif exposed and auth_mode == 'none' and gateway.get('mode') != 'remote':
        emit('cooked', 'configuration exposes gateway beyond localhost with authentication explicitly disabled; verify runtime and upstream controls')

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
    # Deliberately do not guess routing or compose per-agent/provider/sender
    # overrides. These can turn global permissive settings into restricted tools.
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
        # The first release covers top-level Telegram and WhatsApp DM policy.
        # Other adapters/accounts and group/sender policy have separate semantics.
        if name not in ('telegram', 'whatsapp') or any(key in channel for key in ('accounts', 'tools', 'toolsBySender', 'groups')):
            raise ValueError()
        policy = enum(channel, 'dmPolicy', ('open', 'pairing', 'allowlist', 'disabled'))
        incoming = strings(channel, 'allowFrom')
        open_ingress |= policy == 'open' and '*' in incoming

    def matches(patterns):
        return any(p.lower() == 'group:runtime' or fnmatch.fnmatchcase('exec', p.lower()) or p.lower() == 'bash' for p in patterns)

    # Require explicit positive capability; unset defaults do not prove access.
    # alsoAllow expands the base profile; allow instead narrows that profile.
    # Explicit additive grants therefore work even with minimal/messaging.
    capability = profile in ('coding', 'full') or matches(additional) or (profile is None and matches(allow))
    if 'allow' in tools:
        capability = capability and matches(allow)
    capability = capability and not matches(deny)
    permissive_exec = exec_mode == 'full' or (exec_mode is None and security == 'full' and ask == 'off')
    host_exec = host == 'gateway' or (host in (None, 'auto') and sandbox_mode == 'off')
    if open_ingress and capability and permissive_exec and host_exec and sandbox_mode == 'off':
        emit('cooked', 'open DM ingress combines with configured unrestricted host exec and disabled sandbox; host approvals and runtime enforcement remain unverified')
    elif permissive_exec or sandbox_mode == 'off':
        emit('warming', 'explicit permissive exec or disabled sandbox setting; review request access and host approval policy')
    else:
        emit('skip', 'no supported explicit dangerous tool-policy combination found')
    emit('skip', 'static JSON configuration only; credentials, runtime auth enforcement, CLI overrides and host approvals are not verified')
except (OSError, ValueError, TypeError, RecursionError, OverflowError):
    emit('unknown', 'configuration unreadable, oversized, malformed or unsupported (strict JSON and known policy fields only); inspection incomplete')
GATEWAY_PY
    ); then
        result_unknown "OpenClaw configuration parser failed; inspection incomplete"
        return
    fi
    while IFS=$'\t' read -r gateway_severity gateway_message; do
        case "$gateway_severity" in
            cooked) result_cooked "$gateway_message" ;;
            warming) result_warming "$gateway_message" ;;
            unknown) result_unknown "$gateway_message" ;;
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
    local inspection_incomplete=false

    if [[ "$OS_TYPE" == "macos" ]]; then
        # macOS Application Firewall (socketfilterfw)
        if command_exists /usr/libexec/ApplicationFirewall/socketfilterfw; then
            local fw_status
            if ! fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null); then
                result_unknown "macOS Application Firewall status inspection failed — firewall state UNKNOWN"
                inspection_incomplete=true
            elif echo "$fw_status" | grep -qi "enabled"; then
                result_safe "macOS Application Firewall is enabled"
                has_firewall=true
            elif echo "$fw_status" | grep -qi "disabled"; then
                result_cooked "macOS Application Firewall is DISABLED"
            else
                result_unknown "macOS Application Firewall returned an unrecognized status — firewall state UNKNOWN"
                inspection_incomplete=true
            fi
        fi

        # macOS pf (packet filter)
        if command_exists pfctl; then
            local pf_status
            if ! pf_status=$(pfctl -s info 2>/dev/null); then
                result_unknown "macOS pf status inspection failed — firewall state UNKNOWN"
                inspection_incomplete=true
            elif echo "$pf_status" | grep -Eqi "^Status:[[:space:]]+Enabled([[:space:]]|$)"; then
                result_safe "macOS pf (packet filter) is enabled"
                has_firewall=true
            elif ! echo "$pf_status" | grep -Eqi "^Status:[[:space:]]+Disabled([[:space:]]|$)"; then
                result_unknown "macOS pf returned an unrecognized status — firewall state UNKNOWN"
                inspection_incomplete=true
            fi
        fi
    else
        # UFW
        if command_exists ufw; then
            local ufw_status
            if ! ufw_status=$(ufw status 2>/dev/null); then
                result_unknown "UFW status inspection failed — firewall state UNKNOWN"
                inspection_incomplete=true
            elif echo "$ufw_status" | grep -Eqi "^Status:[[:space:]]+active$"; then
                result_safe "UFW firewall is active"
                has_firewall=true
            elif echo "$ufw_status" | grep -Eqi "^Status:[[:space:]]+inactive$"; then
                result_cooked "UFW is installed but INACTIVE"
            else
                result_unknown "UFW returned an unrecognized status — firewall state UNKNOWN"
                inspection_incomplete=true
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
                    result_cooked "firewalld is installed but INACTIVE"
                else
                    result_unknown "firewalld status inspection failed (exit ${firewalld_rc}) — firewall state UNKNOWN"
                    inspection_incomplete=true
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
                elif [[ "$has_firewall" == "false" ]]; then
                    result_warming "iptables has minimal/no rules"
                fi
            else
                result_unknown "iptables ruleset inspection failed — firewall state UNKNOWN"
                inspection_incomplete=true
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
                fi
            else
                result_unknown "nftables ruleset inspection failed — firewall state UNKNOWN"
                inspection_incomplete=true
            fi
        fi
    fi

    if [[ "$has_firewall" == "false" && "$inspection_incomplete" == "false" ]]; then
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
                    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 --noproxy '*' "http://${probe_url_host}:${port}/" 2>/dev/null) || http_code="000"
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

# ─── Check 16: Remote Model Code ──────────────────────────────────────────────

_model_code_snapshot() {
    # Only stdlib process inspection: never import model packages or read configs.
    # ps cannot preserve argv boundaries perfectly; malformed/indirect launches
    # are not treated as proof of a disabled setting. Cap bytes, rows, and time.
    python3 - <<'PY'
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
        result_unknown "Model code inspection unavailable; review active runtime settings (+4)."
        return
    fi
    while IFS='|' read -r state service pid; do
        [[ -z "$state" ]] && continue
        found=true
        case "$state" in
            unavailable)
                result_unknown "Model code inspection unavailable; review active runtime settings (+4)." ;;
            unknown)
                result_unknown "$service PID $pid: could not establish active remote-code configuration from launch arguments (+4); review runtime settings and code." ;;
            absent)
                result_skip "$service PID $pid: no explicit remote-code launch setting observed; configuration, environment overrides and runtime behavior are not inspected." ;;
            disabled)
                result_skip "$service PID $pid: launch setting explicitly disables trust-remote-code; runtime behavior is not verified." ;;
            pinned)
                result_warming "$service PID $pid allows remote model code (--trust-remote-code); an immutable code revision is specified (+4). Review the executable code: a pin does not prove safety." ;;
            enabled)
                result_warming "$service PID $pid allows remote model code (--trust-remote-code) without a verified immutable code revision (+4). Review executable code and pin its revision; a model weights --revision alone is insufficient." ;;
            *)
                result_unknown "Model code inspection unavailable; review active runtime settings (+4)." ;;
        esac
    done <<< "$snapshot"
    if [[ "$found" == false ]]; then
        result_skip "No supported active vLLM or TGI launch found; config files, environment overrides and other runtimes are not inspected."
    fi
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
    check_browser_debugging
    check_mcp_config
    check_agent_gateway
    check_model_code_execution

    print_summary
}

main "$@"
