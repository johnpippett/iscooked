# 🔥 iscooked — Am I Cooked?

[![GitHub stars](https://img.shields.io/github/stars/johnpippett/iscooked?style=social)](https://github.com/johnpippett/iscooked)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.3.0-blue)](https://github.com/johnpippett/iscooked/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)](https://github.com/johnpippett/iscooked)

`iscooked` is a local security scanner for AI services, containers, and agent settings.
It runs as one Bash script and keeps the report on your machine.

## Start a scan

The scanner needs Bash 4 or later. Some macOS installations provide Bash 3.2.
Check your Bash version first:

```bash
bash --version
```

To download, read, and run the scanner:

```bash
curl -fsSL https://iscooked.com/iscooked.com -o iscooked.com
less iscooked.com
bash iscooked.com
```

If you want one command after you trust the source:

```bash
curl -fsSL https://iscooked.com/iscooked.com | bash
```

You can also run a local checkout:

```bash
git clone https://github.com/johnpippett/iscooked.git
cd iscooked
bash iscooked --help
bash iscooked
```

## Scoring

The terminal shows a cooked percentage, a 40-character meter, a verdict, and result counts.
This example is synthetic. It does not scan your machine.

```text
YOUR COOKED SCORE

20% cooked  [▒▒▒▒▒▒▒▒                                ]

SLIGHTLY WARM

0 critical  1 warnings  4 passed
4 unknown  9 skipped  (18 results)

Turn down the heat. Check the warnings above.
```

In this example, one warning and four unknown results add 20 points. Nine skipped results add no points. Start with critical findings. Then review warnings, unknown results, and skipped areas.

The score is a capped heuristic. It is not a probability of compromise.

| Result | Terminal label | Points |
|---|---|---:|
| Critical | `🔥 COOKED` | +10 |
| Warning | `⚠  WARMING UP` | +4 |
| Passed | `✅ SAFE` | +0 |
| Unknown | `❓ UNKNOWN` | +4 |
| Skipped | `⏭  SKIP` | +0 |

| Score | Verdict |
|---:|---|
| 0–14 | `LOOKING FRESH` |
| 15–39 | `SLIGHTLY WARM` |
| 40–69 | `MEDIUM RARE` |
| 70–100 | `FULLY COOKED` |

A critical finding or warning can change a low-score verdict to `SLIGHTLY WARM`. A report with only unknown or skipped results can show `STILL DEFROSTING`. The scanner keeps unknown and skipped counts visible.

## LiteLLM PyPI compromise

LiteLLM `1.107.0` was published to PyPI on 2026-10-21 with a credential stealer, and the `v1.107.0` Docker images on GHCR and Docker Hub carried the same payload. For about three hours that day, the Docker Hub `latest`, `main-latest`, and `main-stable` tags also pointed at the infected image. PyPI removed the release within two hours. The wheels add `cook.pth`, `cook.py`, and `sitecustomize.py` to site-packages, so the stealer runs on every Python start in that environment, even without `import litellm`. On Linux and macOS it also starts a background loader that can run more code every hour. It collects cloud, SSH, CI, browser, and AI tool credentials, and on proxy hosts it also reads provider keys from the proxy database. This is the second LiteLLM compromise this year: `1.82.7` and `1.82.8` carried a similar stealer in March (PYSEC-2026-2).

If you installed or ran an affected version, treat the machine as compromised. Remove the dropped files, reinstall `1.106.2` (the last clean release), redeploy containers from an image pinned by digest, and rotate every credential the machine could reach. That includes the LiteLLM master key and the provider keys stored in the proxy. Check 17 looks for these releases and files, but a clean scan does not undo a theft that already happened.

## What it checks

The scanner has 17 check areas:

| ID | Check area | Looks for |
|---:|---|---|
| 01 | Network Exposure | Common AI service ports and listener bind addresses, including SGLang, the LiteLLM proxy, and the llama.cpp RPC server. |
| 02 | API Authentication | Authentication on selected model-list routes for identified Ollama, LM Studio, and vLLM services. |
| 03 | Model File Permissions | World-readable or world-writable files in common model directories. |
| 04 | Docker / Container Risks | Root users, privileged mode, host networking, daemon sockets, and host-root mounts. |
| 05 | GPU Driver Exposure | GPU device permissions and known management listeners. |
| 06 | Telemetry / Phoning Home | Scanner opt-out values and exact known entries in `/etc/hosts`. |
| 07 | Firewall Status | Recognized Linux and macOS firewall backends. A missing firewall is critical only when an AI service listens beyond localhost; otherwise it is a warning. |
| 08 | SSL/TLS Configuration | Plain HTTP on non-loopback AI service listeners. |
| 09 | AI Process Enumeration | Candidate AI processes and the account that runs each process. |
| 10 | Sensitive File Exposure | World-readable `.env` files that contain common API key names. |
| 11 | History & Logs Leakage | API key patterns in shell history and permissions on common AI log directories. |
| 12 | Ollama-Specific Checks | `OLLAMA_HOST`, `OLLAMA_ORIGINS`, and selected service settings. |
| 13 | Browser Remote Debugging | Chromium-family debugging flags, listeners, and `/json/version` metadata. |
| 14 | MCP Configuration | Selected Model Context Protocol client files, filesystem grants, and permissions. |
| 15 | Agent Gateway Configuration | Selected OpenClaw settings when the installed CLI is 2026.9.3 or later. |
| 16 | Remote Model Code | Remote-code flags in recognized vLLM, Text Generation Inference, and SGLang launches. |
| 17 | Runtime Versions | Ollama, vLLM, and LiteLLM proxy versions below the minimum that fixes reviewed advisories, plus LiteLLM releases that shipped malware. |

## Unknown and skipped results

`UNKNOWN` means that the scanner could not establish a state. `SKIP` means that it did not examine an area. A missing optional tool or unsupported setup can cause a skip. A failed observation can cause an unknown result.

Unknown results add four points. Skipped results add no points. Both results limit coverage. Use the [unknown-results guide](site/unknowns.html) for diagnostic commands and manual checks for firewall, Docker, network, browser, file, agent, model, and environment results.

## Requirements

| Type | Requirement |
|---|---|
| System | Linux or macOS. |
| Shell | Bash 4 or later. Some macOS installations provide Bash 3.2. |
| Required commands | `awk`, `basename`, `cat`, `find`, `grep`, `ps`, `stat`, `tr`, `uname`, `wc`, and `whoami`. |
| Home directory | `HOME` must name an existing absolute directory. |
| Socket evidence | `ss` or `netstat`. Linux falls back to `/proc/net/tcp` when both are missing. Failed inspection produces unknown results. |
| Optional checks | Python 3 enables JSON and structured API, browser, MCP, agent-gateway, and model-code checks. `curl`, `docker`, and `nvidia-smi` enable related probes. |
| Docker timeout | Docker metadata calls use `timeout`, `gtimeout`, or Python 3 for a five-second limit. |

Run `bash --version` to examine the shell version. Elevated privileges can improve some firewall and port checks.

## CLI

For a downloaded scanner, use `bash iscooked.com [options]`. For a local checkout, use `bash iscooked [options]`.

| Option | Action |
|---|---|
| `-h`, `--help` | Show help without a scan. |
| `--version` | Show the scanner version without a scan. |
| `--json` | Write one JSON report. Requires Python 3. |
| `--no-color` | Disable terminal colors. |
| `--fail-on LEVEL` | Select the findings that produce exit status 1. Use `critical`, `warning`, or `unknown`. |

The scanner also disables colors when output is redirected, when `NO_COLOR` is set, or when `TERM=dumb`.

## JSON reports

`--json` writes one report to standard output. It uses `schema_version: 1` and sets `completed: true` after the report is complete. A report contains scanner metadata, the platform, summary counts, score data, coverage counts, and a `findings` array.

Each finding contains a check ID and title, a status, a message, and points. Check IDs identify areas. They do not identify stable rules. Messages can change between releases. The score includes a capped `value` and an uncapped `raw_value`; its `kind` is `heuristic` and it includes unknown results.

Coverage counts distinct areas with observations, unknown results, and skipped results. These groups can overlap. An area can start without complete coverage. Reports can contain local paths and account names. Examine a report before you share it.

Example commands:

```bash
bash iscooked.com --help
bash iscooked.com --version
bash iscooked.com --no-color
bash iscooked.com --json > report.json
bash iscooked.com --json --fail-on critical > report.json
```

## Exit status

Without `--fail-on`, a completed scan returns `0` regardless of its findings. With a failure policy, the scanner returns `1` when the selected results occur:

| Policy | Exit status `1` for |
|---|---|
| `critical` | Critical findings. |
| `warning` | Critical findings or warnings. |
| `unknown` | Critical findings, warnings, or unknown results. |

Skipped results do not trigger these policies. Invalid options, missing required tools, unsupported systems, invalid `HOME`, and unsupported requirements return `2` before the scan. A runtime error can stop a scan before a complete JSON report. JSON consumers must require `completed: true`.

## Coverage limits

The scanner reads local files, process information, listener data, and selected service metadata. It does not change settings, start an MCP server or agent, or load a model. It does not execute model code, retrieve browser tabs or cookies, or connect to a returned WebSocket URL.

Common ports, process names, container names, and paths are identification hints. They do not prove internet reachability or confirm every application identity. A non-loopback listener shows local network exposure. It does not prove internet exposure.

API checks cover `/api/tags` on port `11434` and `/v1/models` on ports `1234` and `8000`. The scanner confirms service identity before it reports API access. It tests one route at a time, does not follow redirects or configured proxies, and uses a five-second total timeout.

Most file checks use Unix mode bits. They do not establish access through every parent directory, access control list, or service boundary. The sensitive-file search stops after 20 files in each bounded search.

The telemetry check reads values in the scanner environment and known host mappings. It does not establish the environment of a running service or analyze outbound traffic. `OLLAMA_NO_CLOUD` false values do not establish an opt-out. The Ollama check separates scanner variables from active service settings.

MCP and OpenClaw checks cover selected files and supported JSON settings. For OpenClaw, the scanner runs `openclaw --version` with a 1.5-second limit. It accepts at most 256 output bytes. Version `2026.9.3` and later can use the selected config checks. A command outside the scanner's fixed search path, a failed command, or an older version gives `UNKNOWN`. The parser is strict, so a newer release that adds unrecognized settings also gives `UNKNOWN`. The CLI version does not prove the version of a running gateway. JSON5, includes, interpolation, overrides, and policy enforcement remain incomplete.

Remote model-code checks cover recognized vLLM, Text Generation Inference, and SGLang command lines. They do not inspect configuration files, environment variables, or other runtimes. A model weights revision does not prove an executable code pin.

Runtime version checks read `/api/version` on Ollama port `11434`, `/version` on vLLM port `8000`, and `/health/readiness` on LiteLLM proxy port `4000`. Each probe is one bounded GET with the same limits as the API checks. vLLM also needs its process name or its `/v1/models` owner before its version is trusted. The minimums cover advisories reviewed on 2026-10-22: Ollama `0.35.0`, vLLM `0.14.1`, and LiteLLM `1.83.14`. An outdated version on a non-loopback listener is critical; on localhost it is a warning. LiteLLM 1.84 and later do not publish their version on the public readiness route, so the check skips them. A version at or above the minimum does not rule out later advisories. A proxy that reports a compromised release (`1.82.7`, `1.82.8`, or `1.107.0`) is critical on any bind.

A malicious `pip install` is not visible from the network, so check 17 also lists common Python environments on disk: system and Homebrew site-packages, the user site, pyenv, conda, pipx, uv tools, and `.venv` or `venv` folders up to two levels under your home folder. It reports a compromised `litellm` dist-info, a `cook.pth` that imports `cook`, a `litellm_init.pth`, and the stealer's marker and lock files in the temp folder. It also lists local Docker image tags, without pulls or registry lookups. It does not look inside images or containers, and it cannot recognize an infected image that was pulled under a mutable tag such as `latest`. The scanner starts Python with `-S`, so its own interpreter never runs a `.pth` file it inspects.

Docker checks inspect known socket paths, the active Unix daemon endpoint, and host-root mounts. A read-only Docker socket mount can still permit daemon API calls. Rootless, proxy, and uncertain access can remain warning or unknown results.

## Privacy

After download, the scan sends no scan report or telemetry to iscooked.com or another remote service. It probes selected local AI and browser endpoints. Reports can contain local paths and account names, so examine them before sharing.

## Develop and test

Run the test suite and the release checks from the repository root:

```bash
python3 -m pytest -q
bash -n iscooked
bash -n site/iscooked.com
cmp iscooked site/iscooked.com
python3 scripts/sync_version.py --check
git diff --check
```

The tests use synthetic fixtures and isolated state. They do not prove behavior on every Linux or macOS installation.

To preview the local website, run:

```bash
python3 scripts/preview.py
```

Then open `http://127.0.0.1:8794`. The preview serves `site/` and does not run the scanner.

`VERSION` is the release version source. Run `python3 scripts/sync_version.py` without an argument after editing `VERSION`. Pass a stable `MAJOR.MINOR.PATCH` value to update `VERSION`, both scanner copies, website labels, and this README badge. Run `python3 scripts/sync_version.py --check` to detect drift without writing files.

## License

[MIT License](LICENSE)

[iscooked.com](https://iscooked.com) · [GitHub repository](https://github.com/johnpippett/iscooked)
