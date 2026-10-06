(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ─── Toggle groups ────────────────────────────────────
  function selectPanel(buttons, panels, buttonKey, panelKey, selected) {
    buttons.forEach((button) =>
      button.setAttribute("aria-pressed", String(button.dataset[buttonKey] === selected)),
    );
    panels.forEach((panel) => {
      panel.hidden = panel.dataset[panelKey] !== selected;
    });
  }

  const categories = $$("[data-category]");
  const coveragePanels = $$("[data-panel]");
  categories.forEach((button) =>
    button.addEventListener("click", () =>
      selectPanel(categories, coveragePanels, "category", "panel", button.dataset.category),
    ),
  );

  const methods = $$("[data-install]");
  const methodPanels = $$("[data-method]");
  methods.forEach((button) =>
    button.addEventListener("click", () => {
      selectPanel(methods, methodPanels, "install", "method", button.dataset.install);
      const status = $("#copy-status");
      if (status) status.textContent = "";
    }),
  );

  // ─── Copy buttons ─────────────────────────────────────
  $$("[data-copy]").forEach((button) => {
    const copyLabel = button.getAttribute("aria-label");
    const status = document.getElementById(button.dataset.status || "copy-status");
    let resetTimer;
    button.addEventListener("click", async () => {
      const command = document.getElementById(button.dataset.copy);
      clearTimeout(resetTimer);
      if (status) status.textContent = "";
      try {
        await navigator.clipboard.writeText(command.textContent);
        button.textContent = "Copied";
        button.setAttribute("aria-label", `${copyLabel}: copied`);
        if (status) status.textContent = "Copied. Paste it into your terminal.";
      } catch {
        const selection = window.getSelection();
        if (selection) {
          const range = document.createRange();
          range.selectNodeContents(command);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        if (status) status.textContent = "Automatic copy is unavailable. The command is selected; copy it with your keyboard.";
      } finally {
        resetTimer = setTimeout(() => {
          button.textContent = "Copy";
          button.setAttribute("aria-label", copyLabel);
        }, 2200);
      }
    });
  });

  // ─── Terminal replay ──────────────────────────────────
  const terminal = $(".terminal");
  const termBody = terminal && $(".terminal-body", terminal);
  const replayButton = terminal && $(".terminal-replay", terminal);
  let playToken = 0;

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function delayFor(line) {
    const text = line.textContent;
    if (!text.trim()) return 40;
    if (line.classList.contains("t-banner")) return 55;
    if (/^\s+\[\d/.test(text)) return 120;
    if (/COOKED|WARMING|SAFE|SKIP|UNKNOWN/.test(text)) return 260;
    if (/^\s+─/.test(text)) return 25;
    return 80;
  }

  async function play() {
    const token = ++playToken;
    const lines = $$(".ln", termBody);
    const cmd = $(".t-cmd", termBody);
    const scoreValue = $(".t-heat", lines.find((l) => l.textContent.includes("% cooked")));
    const barSpan = scoreValue && scoreValue.parentElement.querySelector(".t-red");
    const fullCmd = cmd.dataset.full || (cmd.dataset.full = cmd.textContent);
    const fullBar = barSpan && (barSpan.dataset.full || (barSpan.dataset.full = barSpan.textContent));
    const fullScore = scoreValue && (scoreValue.dataset.full || (scoreValue.dataset.full = scoreValue.textContent));

    terminal.classList.add("playing");
    lines.forEach((line) => line.classList.add("pending"));
    termBody.scrollTop = 0;

    lines[0].classList.remove("pending");
    cmd.textContent = "";
    cmd.classList.add("caret");
    await wait(500);
    for (const ch of fullCmd) {
      if (token !== playToken) return;
      cmd.textContent += ch;
      await wait(45);
    }
    cmd.classList.remove("caret");
    await wait(350);

    for (const line of lines.slice(1)) {
      if (token !== playToken) return;
      line.classList.remove("pending");
      termBody.scrollTop = termBody.scrollHeight;
      if (barSpan && line.contains(barSpan)) {
        const target = parseInt(fullScore, 10);
        const filled = fullBar.replace(/ /g, "").length;
        for (let i = 0; i <= filled; i++) {
          if (token !== playToken) return;
          barSpan.textContent = fullBar.slice(0, i) + " ".repeat(fullBar.length - i);
          scoreValue.textContent = Math.round((target * i) / filled) + "%";
          await wait(55);
        }
        await wait(300);
      } else {
        await wait(delayFor(line));
      }
    }
    terminal.classList.remove("playing");
  }

  if (terminal && termBody) {
    replayButton.addEventListener("click", () => {
      play();
    });
    if (!reduceMotion && "IntersectionObserver" in window) {
      const observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting)) {
            observer.disconnect();
            play();
          }
        },
        { threshold: 0.35 },
      );
      observer.observe(terminal);
    }
  }

  // ─── Doneness simulator ───────────────────────────────
  const counts = { critical: 2, warning: 2, unknown: 0, passed: 3, skipped: 11 };
  const KEYS = ["critical", "warning", "unknown", "passed", "skipped"];
  const COLOR_CLASS = { red: "t-red", yellow: "t-yellow", cyan: "t-cyan", green: "t-green" };
  const INK_CLASS = { red: "ink-red", yellow: "ink-yellow", cyan: "ink-cyan", green: "ink-green" };

  function span(cls, text) {
    const el = document.createElement("span");
    el.className = cls;
    el.textContent = text;
    return el;
  }

  function renderSim() {
    if (!window.IsCooked || !$("#sim-value")) return;
    const v = window.IsCooked.verdict(counts);
    KEYS.forEach((key) => {
      $(`[data-count="${key}"]`).textContent = counts[key];
    });
    $$("[data-step]").forEach((button) => {
      if (Number(button.dataset.delta) < 0) button.disabled = counts[button.dataset.step] === 0;
      else button.disabled = counts[button.dataset.step] >= 30;
    });

    const value = $("#sim-value");
    value.textContent = v.score;
    const verdictEl = $("#sim-verdict");
    verdictEl.textContent = v.text;
    [value.parentElement, verdictEl].forEach((el) => {
      el.classList.remove(...Object.values(INK_CLASS));
      el.classList.add(INK_CLASS[v.color]);
    });
    $("#sim-marker").style.left = `${v.score}%`;
    const temp = $("#thermal-temp");
    if (temp) temp.textContent = `${v.score}%`;
    const thermal = $(".thermal canvas");
    if (thermal) thermal.dataset.score = String(v.score);
    document.dispatchEvent(new CustomEvent("iscooked:score", { detail: { score: v.score, target: ".sim-output" } }));

    const color = COLOR_CLASS[v.color];
    const term = $("#sim-terminal");
    term.replaceChildren(
      "  ", span("t-heat " + color, `${v.score}%`), " ", span("t-dim", "cooked"),
      "  [", span(color, v.bar), "]\n\n  ",
      span("t-bold " + color, v.text), "\n\n  ",
      span("t-red t-bold", String(counts.critical)), " critical  ",
      span("t-yellow t-bold", String(counts.warning)), " warnings  ",
      span("t-green t-bold", String(counts.passed)), " passed\n  ",
      span("t-cyan", String(counts.unknown)), " unknown  ",
      span("t-dim", `${counts.skipped} skipped  (${v.total} results)`), "\n\n  ",
      span(COLOR_CLASS[v.message.color], v.message.text),
    );

    const parts = [];
    if (counts.critical) parts.push(`${counts.critical} × 10`);
    if (counts.warning) parts.push(`${counts.warning} × 4`);
    if (counts.unknown) parts.push(`${counts.unknown} × 4`);
    const sum = parts.length ? `${parts.join(" + ")} = ${v.raw}` : "No points";
    const capped = v.raw > 100 ? `, capped at 100` : "";
    let note;
    if (v.level === "defrosting" && counts.critical + counts.warning + counts.passed === 0) {
      note = "Nothing passed and nothing failed, so the scanner will not call it fresh. Resolve the unknowns and skips first.";
    } else if (v.level === "defrosting") {
      note = "Only unknown or skipped results add heat here, so the verdict stays on ice instead of fresh.";
    } else if (counts.critical > 0 && v.score < 15) {
      note = "A critical finding lifts any low score to at least Slightly warm.";
    } else if (counts.critical > 0) {
      note = "Any critical finding turns the verdict red, whatever the number.";
    } else if (counts.warning > 0 && v.score < 15) {
      note = "A warning lifts a low score to at least Slightly warm.";
    } else if (v.level === "fresh") {
      note = "No heat from the checks that ran. A low score is still not a guarantee.";
    } else {
      note = "Unknown results count like warnings. The scanner could not rule them out.";
    }
    const strong = document.createElement("strong");
    strong.textContent = `${sum}${capped}.`;
    $("#sim-explain").replaceChildren(strong, " " + note);
  }

  $$("[data-step]").forEach((button) =>
    button.addEventListener("click", () => {
      const key = button.dataset.step;
      counts[key] = Math.max(0, Math.min(30, counts[key] + Number(button.dataset.delta)));
      $$("[data-preset]").forEach((chip) => chip.setAttribute("aria-pressed", "false"));
      renderSim();
    }),
  );
  $$("[data-preset]").forEach((chip) => {
    chip.setAttribute("aria-pressed", "false");
    chip.addEventListener("click", () => {
      chip.dataset.preset.split(",").map(Number).forEach((n, i) => {
        counts[KEYS[i]] = n;
      });
      $$("[data-preset]").forEach((other) => other.setAttribute("aria-pressed", String(other === chip)));
      renderSim();
    });
  });

  // ─── Boot ─────────────────────────────────────────────
  $$(".enhancement").forEach((element) => {
    element.hidden = false;
  });
  if (categories.length) selectPanel(categories, coveragePanels, "category", "panel", "network");
  if (methods.length) selectPanel(methods, methodPanels, "install", "method", "quick");
  renderSim();
  document.documentElement.classList.add("enhanced");
})();
