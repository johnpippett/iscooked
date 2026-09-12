# 🔥 iscooked.com — Am I Cooked?

[![GitHub stars](https://img.shields.io/github/stars/johnpippett/iscooked?style=social)](https://github.com/johnpippett/iscooked)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.1.0-blue)](https://github.com/johnpippett/iscooked/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)](https://github.com/johnpippett/iscooked)

**Local AI security scanner.** One command to find out if your Ollama, LM Studio, or self-hosted LLM setup is leaking like a sieve.

```bash
curl -fsSL https://iscooked.com/iscooked.com | bash
```

Or download and run manually:

```bash
wget https://iscooked.com/iscooked.com
chmod +x iscooked.com
./iscooked.com
```

## What it checks

| Check | What it looks for |
|---|---|
| **Network Exposure** | AI services listening on 0.0.0.0 instead of localhost |
| **API Authentication** | Read-only model-list endpoints for identified Ollama, LM Studio, and vLLM services |
| **File Permissions** | Model files and directories world-readable/writable |
| **Docker Risks** | Root users, privileged mode, host networking, Docker daemon sockets, and host-root mounts |
| **GPU Exposure** | NVIDIA/AMD device permissions and management endpoints |
| **Telemetry** | Active connections to known telemetry domains |
| **Firewall Status** | UFW, firewalld, iptables, nftables — is anything running? |
| **SSL/TLS** | AI services exposed over plain HTTP on non-localhost |
| **Process Audit** | AI processes and what user they're running as |
| **Sensitive Files** | .env files with API keys readable by other users |
| **History & Logs** | API keys leaked in shell history, world-readable log dirs |
| **Ollama Config** | OLLAMA_HOST, OLLAMA_ORIGINS, systemd service checks |
| **Browser Control** | Browser remote-debugging listeners, including non-default ports |
| **MCP Configuration** | Broad filesystem grants and local configuration permission risks |
| **Agent Gateways** | OpenClaw gateway authentication and tool-access configuration |
| **Model Code Execution** | Recognized running model servers allowing remote model code |

## Example output

```
  🔥 COOKED   Ollama (port 11434) is listening on ALL interfaces
  ✅ SAFE      LM Studio (port 1234) is bound to localhost only
  ⚠  WARMING UP  Ollama API is responding without authentication
  🔥 COOKED   Model files are world-readable on disk
  🔥 COOKED   AI container running as root with host networking
  🔥 COOKED   NVIDIA device exposed to all local users
  🔥 COOKED   .env file with API key is world-readable
  🔥 COOKED   No active firewall detected!
  🔥 COOKED   Shell history contains ~3 potential API key(s)

  YOUR COOKED SCORE

  74% cooked  [██████████████████████████████          ]

  FULLY COOKED

  7 critical  1 warnings  2 passed

  You are absolutely cooked. Fix the critical issues above ASAP.
```

## Scoring

Your **cooked score** ranges from 0–100%:

- **0–14%** — **Looking Fresh.** Your setup is locked down.
- **15–39%** — **Slightly Warm.** A few things to tighten up.
- **40–69%** — **Medium Rare.** Address those warnings.
- **70–100%** — **Fully Cooked.** Fix the critical issues now.

## Requirements

- Bash 4+
- Standard Unix tools (ss/netstat, ps, stat, find)
- Optional: Python 3 (for structured API, browser, MCP, gateway, and model-code checks), `curl` (for API/browser probes), `docker` (for container checks), `nvidia-smi` (for GPU checks)
- Docker metadata calls use `timeout`, `gtimeout`, or Python 3 to enforce a five-second timeout. If none is available, container inspection is reported as incomplete.
- Elevated privileges can improve some firewall and port checks

## Agent-check coverage

The scanner remains one downloadable Bash file. Optional checks report `SKIP`
when their dependencies or supported configurations are absent. It never starts
an MCP server, loads a model, or executes a configured agent to inspect it.

- **API authentication:** `/api/tags` on port 11434 and `/v1/models` on ports
  1234/8000. Service identity and model-list metadata are checked before reporting
  unauthenticated access. A 401/403 conclusion applies only to the probed route,
  not every endpoint of the service. Unknown services are not labeled as AI
  merely because they occupy a familiar port. Requests do not follow redirects
  or use configured proxies; each has a five-second total timeout.
- **Docker access:** known Docker socket paths, the active Unix daemon endpoint,
  and host-root mounts. An identified rootful daemon socket mounted in a root container with
  no user-namespace isolation is critical. Rootless, proxy, or uncertain access
  warns. A read-only socket mount does not make Docker API operations read-only.
- **MCP:** Claude Desktop JSON configuration on Linux/macOS, Claude Code's
  `.mcp.json` in the current directory and `~/.claude.json`, and Cursor's user
  and current-project `.cursor/mcp.json`. The scanner recognizes explicit
  filesystem-server grants and known shell-server configuration. It checks
  configuration access without printing credentials. Other clients, unresolved
  variables, and permissions it cannot establish are reported as limited or
  incomplete coverage.
- **Browser control:** known Chromium-family processes with a network debugging
  flag are correlated with listening sockets and `/json/version` metadata.
  Custom ports, IPv4/IPv6, and pipe-only debugging are distinguished. Metadata
  requests never retrieve tabs or cookies or connect to a returned WebSocket URL.
  A non-loopback bind establishes local network exposure, not internet reachability.
- **OpenClaw:** strict JSON at `~/.openclaw/openclaw.json` or the literal path in
  `OPENCLAW_CONFIG_PATH`. Checks explicit gateway bind/auth settings and supported
  global tool/sandbox settings with Telegram/WhatsApp DM policies. JSON5,
  includes, interpolation, per-agent/provider/sender overrides, and unsupported
  channel policies are reported as incomplete. The scanner does not execute
  OpenClaw's policy resolver or verify enforcement of a configured token.
- **Model code:** recognized running `vllm serve`, Python vLLM API-server module,
  and `text-generation-launcher` (TGI) command lines. Explicit remote-code flags
  warn even when an immutable code revision is specified. A model weights
  revision alone does not verify a code pin. Config files, process environment
  variables, and other runtimes are not inspected; absent/disabled command-line
  flags receive a scoped skip rather than a guarantee about runtime behavior.

Configuration findings describe settings, not proof that an agent is running
or that malicious code has executed. The cooked score is an additive heuristic,
not a probability of compromise: critical findings add 10 points; warnings and
inconclusive (`UNKNOWN`) findings add 4. The score is capped at 100. A skipped
check adds no points and does not establish that its area is safe. Distinct
risks, such as an exposed listener and its missing API authentication, can both
contribute to the score.

## Privacy

iscooked.com runs **entirely on your machine**. It sends no telemetry and phones home to absolutely nobody. The only network activity is checking whether local AI services are reachable on localhost or on the local bind address they already expose.

## Contributing

### Versioning

`VERSION` is the release version source. For a release, run:

```bash
python3 scripts/sync_version.py 1.2.0
```

This updates `VERSION`, both standalone scanner copies, the website badge and
terminal demo, and this README's badge. Run without a version to synchronize
after editing `VERSION` directly. Versioning happens during preparation; the
downloaded scanner needs no additional file or network request.

Before publishing, run `python3 scripts/sync_version.py --check` and the test
suite. The check detects stale versions without writing files, and the test
suite includes it. Use patch bumps for fixes, minor bumps for compatible new
checks, and major bumps for breaking changes. A bump does not deploy or tag a release.

PRs welcome! Some ideas:

- [ ] Add checks for more AI tools (KoboldCpp, TabbyAPI, Whisper, etc.)
- [ ] JSON output mode for CI/CD integration
- [ ] Auto-fix mode for common issues
- [ ] macOS-specific checks
- [ ] WSL-specific checks

## License

MIT — do whatever you want with it.

---

Built by a cybersecurity engineer who runs local LLMs. [iscooked.com](https://iscooked.com)
