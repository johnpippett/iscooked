(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const MAX_BYTES = 5 * 1024 * 1024;
  const STATUSES = ["critical", "warning", "unknown", "passed", "skipped"];
  const RANK = { critical: 0, warning: 1, unknown: 2, passed: 3, skipped: 4 };
  const LABEL = {
    critical: "Critical",
    warning: "Warning",
    unknown: "Unknown",
    passed: "Passed",
    skipped: "Skipped",
  };
  const TERM_CLASS = { red: "t-red", yellow: "t-yellow", cyan: "t-cyan", green: "t-green" };
  // Check id → section of unknowns.html that explains incomplete results.
  const GUIDE = {
    "01": "network", "02": "network", "03": "files", "04": "docker",
    "05": "runtime", "06": "runtime", "07": "firewall", "08": "network",
    "09": "runtime", "10": "files", "11": "files", "12": "runtime",
    "13": "network", "14": "configuration", "15": "configuration", "16": "runtime",
  };

  const EXAMPLE = {
    schema_version: 1,
    scanner: { name: "iscooked", version: "1.2.1" },
    platform: "linux",
    completed: true,
    summary: {
      status: "critical",
      counts: { total: 12, critical: 2, warning: 2, passed: 3, unknown: 1, skipped: 4 },
      score: { value: 32, raw_value: 32, maximum: 100, kind: "heuristic", includes_unknown: true },
    },
    coverage: { areas_started: 16, areas_with_observations: 6, areas_with_unknown: 1, areas_with_skips: 4 },
    findings: [
      { check: { id: "01", title: "Network Exposure" }, status: "critical", points: 10,
        message: "Unidentified service on port 8000 (commonly vLLM) is listening on ALL interfaces" },
      { check: { id: "01", title: "Network Exposure" }, status: "passed", points: 0,
        message: "Unidentified service on port 1234 (commonly LM Studio) is bound to localhost only" },
      { check: { id: "02", title: "API Authentication" }, status: "warning", points: 4,
        message: "Ollama /api/tags on port 11434 accessible without authentication on localhost; other routes were not tested" },
      { check: { id: "03", title: "Model File Permissions" }, status: "critical", points: 10,
        message: "Files in /srv/models are world-writable!" },
      { check: { id: "04", title: "Docker / Container Risks" }, status: "unknown", points: 4,
        message: "Docker daemon inspection incomplete — UNKNOWN (unreachable or bounded command unavailable)" },
      { check: { id: "05", title: "GPU Driver Exposure" }, status: "skipped", points: 0,
        message: "No GPU devices detected" },
      { check: { id: "06", title: "Telemetry / Phoning Home" }, status: "skipped", points: 0,
        message: "No supported opt-out evidence found; outbound traffic and running service settings are not assessed" },
      { check: { id: "07", title: "Firewall Status" }, status: "passed", points: 0,
        message: "UFW firewall is active" },
      { check: { id: "10", title: "Sensitive File Exposure" }, status: "passed", points: 0,
        message: "No world-readable .env files with API keys found" },
      { check: { id: "13", title: "Browser Remote Debugging" }, status: "skipped", points: 0,
        message: "No Chromium remote debugging listener found" },
      { check: { id: "14", title: "MCP Configuration" }, status: "warning", points: 4,
        message: "Claude Desktop Linux: filesystem server grants access to entire home directory; narrow grants to required project directories" },
      { check: { id: "16", title: "Remote Model Code" }, status: "skipped", points: 0,
        message: "No supported active vLLM or TGI launch found; config files, environment overrides and other runtimes are not inspected." },
    ],
  };

  const state = { report: null, filter: "all", worstFirst: true, example: false };

  // ─── Parsing ──────────────────────────────────────────
  function fail(message) {
    const error = new Error(message);
    error.userFacing = true;
    throw error;
  }

  function normalize(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      fail("This JSON is not an iscooked report. Create one with bash iscooked.com --json > cooked.json.");
    }
    if (!data.scanner || data.scanner.name !== "iscooked") {
      fail("This JSON was not written by iscooked. The scanner.name field is missing or different.");
    }
    if (data.schema_version !== 1) {
      fail(`This viewer reads report schema 1. The file uses schema ${String(data.schema_version)}. Update the viewer page or the scanner.`);
    }
    if (!Array.isArray(data.findings)) {
      fail("The report has no findings list. The file may be truncated; run the scan again.");
    }
    const findings = data.findings.map((f, index) => {
      const status = f && STATUSES.includes(f.status) ? f.status : null;
      if (!status || !f.check || typeof f.message !== "string") {
        fail(`Finding ${index + 1} is malformed. The file may have been edited or truncated.`);
      }
      return {
        id: String(f.check.id ?? "??"),
        title: String(f.check.title ?? "Unnamed check"),
        status,
        message: f.message,
        points: Number(f.points) || 0,
        order: index,
      };
    });
    const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
    findings.forEach((f) => counts[f.status]++);
    const raw = findings.reduce((sum, f) => sum + f.points, 0);
    const reportedRaw = Number(data.summary?.score?.raw_value);
    return {
      version: String(data.scanner.version ?? "unknown"),
      platform: String(data.platform ?? "unknown"),
      completed: data.completed !== false,
      coverage: data.coverage || {},
      counts,
      raw: Number.isFinite(reportedRaw) ? reportedRaw : raw,
      findings,
    };
  }

  // ─── Rendering ────────────────────────────────────────
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") node.className = value;
      else node.setAttribute(key, value);
    }
    node.append(...children);
    return node;
  }

  function pill(status) {
    return el("span", { class: `pill pill-${status}` }, LABEL[status]);
  }

  function renderSummary(report) {
    const v = window.IsCooked.verdict(report.counts, report.raw);
    report.verdict = v;
    $("#r-score").textContent = v.score;
    const verdict = $("#r-verdict");
    verdict.textContent = v.text;
    verdict.className = `summary-verdict ${TERM_CLASS[v.color]}`;
    $("#r-score").parentElement.className = `summary-value ${TERM_CLASS[v.color]}`;
    $("#r-marker").style.left = `${v.score}%`;
    const message = $("#r-message");
    message.textContent = v.message.text;
    message.className = `summary-message ${TERM_CLASS[v.message.color]}`;

    const c = report.counts;
    const cov = report.coverage;
    const rows = [
      ["Scanner", `v${report.version} on ${report.platform}`],
      ["Results", `${v.total} total · ${c.critical} critical · ${c.warning} warnings · ${c.passed} passed · ${c.unknown} unknown · ${c.skipped} skipped`],
      ["Points", v.raw > 100 ? `${v.raw} raw, capped at 100` : `${v.raw}`],
    ];
    if (Number.isFinite(cov.areas_started)) {
      rows.push(["Coverage", `${cov.areas_started} areas started · ${cov.areas_with_observations ?? 0} with observations · ${cov.areas_with_unknown ?? 0} with unknowns · ${cov.areas_with_skips ?? 0} with skips`]);
    }
    if (!report.completed) rows.push(["Status", "Scan did not complete"]);
    $("#r-meta").replaceChildren(...rows.flatMap(([k, val]) => [el("dt", {}, k), el("dd", {}, val)]));
  }

  function renderFilters(report) {
    const buttons = [["all", "All", report.findings.length], ...STATUSES.map((s) => [s, LABEL[s], report.counts[s]])];
    $("#r-filters").replaceChildren(
      ...buttons.map(([key, label, n]) => {
        const button = el("button", { type: "button", "aria-pressed": String(state.filter === key) });
        if (key !== "all") button.append(el("span", { class: `dot dot-${key}`, "aria-hidden": "true" }));
        button.append(label, " ", el("b", {}, String(n)));
        button.disabled = key !== "all" && n === 0;
        button.addEventListener("click", () => {
          state.filter = key;
          render();
        });
        return button;
      }),
    );
  }

  function renderChecks(report) {
    const groups = new Map();
    report.findings
      .filter((f) => state.filter === "all" || f.status === state.filter)
      .forEach((f) => {
        const key = `${f.id}\u0000${f.title}`;
        if (!groups.has(key)) groups.set(key, { id: f.id, title: f.title, items: [], first: f.order });
        groups.get(key).items.push(f);
      });
    let list = [...groups.values()];
    list.forEach((g) => {
      g.worst = Math.min(...g.items.map((f) => RANK[f.status]));
      if (state.worstFirst) g.items.sort((a, b) => RANK[a.status] - RANK[b.status] || a.order - b.order);
    });
    list.sort((a, b) => (state.worstFirst ? a.worst - b.worst : 0) || a.first - b.first);

    if (!list.length) {
      $("#r-checks").replaceChildren(el("p", { class: "empty-filter" }, "No findings match this filter."));
      return;
    }
    $("#r-checks").replaceChildren(
      ...list.map((g) =>
        el(
          "article",
          { class: "check-group" },
          el("div", { class: "check-group-head" },
            el("span", { class: "check-group-id" }, `Check ${g.id}`),
            el("h3", { class: "check-group-title" }, g.title)),
          el(
            "ul",
            { class: "finding-list" },
            ...g.items.map((f) => {
              const message = el("span", { class: "finding-message" }, f.message);
              if ((f.status === "unknown" || f.status === "skipped") && GUIDE[f.id]) {
                message.append(el("a", { href: `./unknowns.html#${GUIDE[f.id]}` }, "Next step ↗"));
              }
              return el("li", { class: "finding-row" }, pill(f.status), message);
            }),
          ),
        ),
      ),
    );
  }

  function render() {
    const report = state.report;
    if (!report) return;
    $("#report-view").hidden = false;
    $("#example-banner").hidden = !state.example;
    renderSummary(report);
    renderFilters(report);
    renderChecks(report);
    $("#r-sort").setAttribute("aria-pressed", String(state.worstFirst));
    $("#r-sort").textContent = state.worstFirst ? "Worst first" : "Check order";
  }

  // ─── Markdown export ──────────────────────────────────
  function cell(text) {
    return String(text).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\s+/g, " ");
  }

  function toMarkdown(report) {
    const v = report.verdict;
    const c = report.counts;
    const lines = [
      `## iscooked: ${v.score}% cooked (${v.text})`,
      "",
      `Scanner v${cell(report.version)} on ${cell(report.platform)} · ${v.total} results: ${c.critical} critical, ${c.warning} warnings, ${c.passed} passed, ${c.unknown} unknown, ${c.skipped} skipped`,
      "",
    ];
    const notable = report.findings
      .filter((f) => f.status !== "passed" && f.status !== "skipped")
      .sort((a, b) => RANK[a.status] - RANK[b.status] || a.order - b.order);
    if (notable.length) {
      lines.push("| Status | Check | Finding |", "|---|---|---|");
      notable.forEach((f) => lines.push(`| ${LABEL[f.status]} | ${cell(f.id)} ${cell(f.title)} | ${cell(f.message)} |`));
      lines.push("");
    } else {
      lines.push("No critical findings, warnings, or unknown results.", "");
    }
    lines.push("_Passed and skipped results omitted. The score is a heuristic, not a probability of compromise._");
    return lines.join("\n");
  }

  // ─── Loading ──────────────────────────────────────────
  function showError(message) {
    const box = $("#loader-error");
    box.textContent = message;
    box.hidden = !message;
  }

  function loadText(text, { example = false } = {}) {
    try {
      const data = typeof text === "string" ? JSON.parse(text) : text;
      state.report = normalize(data);
      state.example = example;
      state.filter = "all";
      showError("");
      render();
      if (!example) {
        $("#paste-box").hidden = true;
        $("#report-view").scrollIntoView({ behavior: "smooth", block: "start" });
      }
    } catch (error) {
      showError(
        error.userFacing
          ? error.message
          : "This file is not valid JSON. Save the report with bash iscooked.com --json > cooked.json and keep only the JSON output.",
      );
    }
  }

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      showError("This file is larger than 5 MB. An iscooked report is usually a few kilobytes; check that you chose the right file.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => loadText(String(reader.result));
    reader.onerror = () => showError("Your browser could not read this file. Try choosing it again.");
    reader.readAsText(file);
  }

  $("#report-file").addEventListener("change", (event) => {
    loadFile(event.target.files[0]);
    event.target.value = "";
  });

  const dropzone = $("#dropzone");
  let dragDepth = 0;
  document.addEventListener("dragenter", (event) => {
    if (![...(event.dataTransfer?.types || [])].includes("Files")) return;
    dragDepth++;
    dropzone.classList.add("dragging");
  });
  document.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) dropzone.classList.remove("dragging");
  });
  document.addEventListener("dragover", (event) => event.preventDefault());
  document.addEventListener("drop", (event) => {
    event.preventDefault();
    dragDepth = 0;
    dropzone.classList.remove("dragging");
    loadFile(event.dataTransfer?.files?.[0]);
  });

  document.addEventListener("paste", (event) => {
    if (event.target.closest && event.target.closest("textarea, input")) return;
    const text = event.clipboardData?.getData("text");
    if (text && text.trim().startsWith("{")) {
      event.preventDefault();
      loadText(text);
    }
  });

  $("#toggle-paste").addEventListener("click", () => {
    const box = $("#paste-box");
    box.hidden = !box.hidden;
    if (!box.hidden) $("#paste-input").focus();
  });
  $("#paste-submit").addEventListener("click", () => loadText($("#paste-input").value));
  $("#load-example").addEventListener("click", () => {
    loadText(EXAMPLE, { example: true });
    $("#report-view").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("#r-sort").addEventListener("click", () => {
    state.worstFirst = !state.worstFirst;
    render();
  });

  $("#r-copy").addEventListener("click", async () => {
    if (!state.report) return;
    const markdown = toMarkdown(state.report);
    const status = $("#r-copy-status");
    try {
      await navigator.clipboard.writeText(markdown);
      status.textContent = "Markdown copied. Review it for paths and hostnames before you share it.";
    } catch {
      $("#paste-box").hidden = false;
      $("#paste-input").value = markdown;
      $("#paste-input").select();
      status.textContent = "Automatic copy is unavailable. The Markdown is selected in the box above.";
    }
  });

  // Open in a realistic state: the example report, clearly labeled.
  loadText(EXAMPLE, { example: true });
})();
