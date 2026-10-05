// Mirrors print_summary() and summary_status() in the scanner. Keep in sync.
(() => {
  "use strict";

  const POINTS = { critical: 10, warning: 4, unknown: 4, passed: 0, skipped: 0 };
  const BAR_WIDTH = 40;

  function verdict(counts, rawScore) {
    const c = counts.critical | 0;
    const w = counts.warning | 0;
    const u = counts.unknown | 0;
    const p = counts.passed | 0;
    const s = counts.skipped | 0;
    const total = c + w + u + p + s;
    const raw =
      rawScore == null ? c * POINTS.critical + w * POINTS.warning + u * POINTS.unknown : rawScore;
    const score = Math.min(raw, 100);

    let level;
    if (score >= 70) level = "cooked";
    else if (score >= 40) level = "medium";
    else if (score >= 15) level = "warm";
    else level = "fresh";

    if (c + w + p === 0) {
      level = "defrosting";
    } else if (score < 15) {
      if (c + w > 0) level = "warm";
      else if (u + s > 0) level = "defrosting";
    }

    const LEVELS = {
      cooked: { text: "FULLY COOKED", color: "red", bar: "█" },
      medium: { text: "MEDIUM RARE", color: "yellow", bar: "▓" },
      warm: { text: "SLIGHTLY WARM", color: "cyan", bar: "▒" },
      fresh: { text: "LOOKING FRESH", color: "green", bar: "░" },
      defrosting: { text: "STILL DEFROSTING", color: "cyan", bar: "░" },
    };
    const info = LEVELS[level];
    const color = c > 0 ? "red" : info.color;

    let status;
    if (c > 0) status = "critical";
    else if (w > 0) status = "warning";
    else if (u > 0 || s > 0 || total === 0) status = "inconclusive";
    else status = "no_findings";

    const MESSAGES = {
      critical: { text: "Fix critical findings first.", color: "red" },
      warning: { text: "Turn down the heat. Check the warnings above.", color: "yellow" },
      inconclusive: { text: "Some checks are still on ice. Check unknowns and skips.", color: "cyan" },
      no_findings: { text: "No heat from the checks that ran.", color: "green" },
    };

    const filled = Math.floor((score * BAR_WIDTH) / 100);
    return {
      score,
      raw,
      level,
      text: info.text,
      color,
      status,
      message: MESSAGES[status],
      bar: info.bar.repeat(filled) + " ".repeat(BAR_WIDTH - filled),
      total,
    };
  }

  window.IsCooked = { verdict, POINTS };
})();
