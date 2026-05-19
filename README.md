# 🔥 iscooked.com — Am I Cooked?

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
| **API Authentication** | Ollama, LM Studio, Open WebUI running without auth |
| **File Permissions** | Model files and directories world-readable/writable |
| **Docker Risks** | AI containers running as root, privileged mode, host networking |
| **GPU Exposure** | NVIDIA/AMD device permissions and management endpoints |
| **Telemetry** | Active connections to known telemetry domains |
| **Firewall Status** | UFW, firewalld, iptables, nftables — is anything running? |
| **SSL/TLS** | AI services exposed over plain HTTP on non-localhost |
| **Process Audit** | AI processes and what user they're running as |
| **Sensitive Files** | .env files with API keys readable by other users |
| **History & Logs** | API keys leaked in shell history, world-readable log dirs |
| **Ollama Config** | OLLAMA_HOST, OLLAMA_ORIGINS, systemd service checks |

## Example output

```
  🔥 COOKED   Ollama (port 11434) is listening on ALL interfaces
  ✅ SAFE      LM Studio (port 1234) is bound to localhost only
  ⚠  WARMING UP  Ollama API is responding without authentication
  🔥 COOKED   No active firewall detected!
  🔥 COOKED   Shell history contains ~3 potential API key(s)

  YOUR COOKED SCORE

  73% cooked  [██████████████████████████████          ]

  FULLY COOKED

  3 critical  1 warnings  2 passed

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
- Optional: `curl` (for API auth checks), `docker` (for container checks), `nvidia-smi` (for GPU checks)
- Elevated privileges can improve some firewall and port checks

## Privacy

iscooked.com runs **entirely on your machine**. It sends no telemetry and phones home to absolutely nobody. The only network activity is checking whether local AI services are reachable on localhost or on the local bind address they already expose.

## Contributing

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
