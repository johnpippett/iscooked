(() => {
  "use strict";

  const filters = [...document.querySelectorAll("[data-filter]")];
  const findings = [...document.querySelectorAll("[data-severity]")];
  const expandButton = document.querySelector("#show-findings");
  const findingCount = document.querySelector("#finding-count");
  let activeFilter = "all";
  let expanded = false;

  function updateFindings() {
    const matching = findings.filter(
      (row) => activeFilter === "all" || row.dataset.severity === activeFilter,
    );
    const shown =
      activeFilter === "all" && !expanded ? matching.slice(0, 4) : matching;
    findings.forEach((row) => {
      row.hidden = !shown.includes(row);
    });
    filters.forEach((button) =>
      button.setAttribute(
        "aria-pressed",
        String(button.dataset.filter === activeFilter),
      ),
    );
    findingCount.textContent = `${shown.length} of ${matching.length} example findings`;
    expandButton.hidden = activeFilter !== "all";
    expandButton.setAttribute("aria-expanded", String(expanded));
    document.querySelector("#show-findings-label").textContent = expanded
      ? "Show fewer"
      : "Show all 7";
    document.querySelector("#show-findings-icon").textContent = expanded
      ? "↑"
      : "↗";
  }

  filters.forEach((button) =>
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      updateFindings();
    }),
  );
  expandButton.addEventListener("click", () => {
    expanded = !expanded;
    updateFindings();
  });

  function selectPanel(buttons, panels, buttonKey, panelKey, selected) {
    buttons.forEach((button) =>
      button.setAttribute(
        "aria-pressed",
        String(button.dataset[buttonKey] === selected),
      ),
    );
    panels.forEach((panel) => {
      panel.hidden = panel.dataset[panelKey] !== selected;
    });
  }

  const categories = [...document.querySelectorAll("[data-category]")];
  const coveragePanels = [...document.querySelectorAll("[data-panel]")];
  categories.forEach((button) =>
    button.addEventListener("click", () => {
      selectPanel(
        categories,
        coveragePanels,
        "category",
        "panel",
        button.dataset.category,
      );
    }),
  );

  const methods = [...document.querySelectorAll("[data-install]")];
  const methodPanels = [...document.querySelectorAll("[data-method]")];
  methods.forEach((button) =>
    button.addEventListener("click", () => {
      selectPanel(
        methods,
        methodPanels,
        "install",
        "method",
        button.dataset.install,
      );
      document.querySelector("#copy-status").textContent = "";
    }),
  );

  const copyStatus = document.querySelector("#copy-status");
  document.querySelectorAll("[data-copy]").forEach((button) => {
    const copyLabel = button.getAttribute("aria-label");
    let resetTimer;
    button.addEventListener("click", async () => {
      const command = document.getElementById(button.dataset.copy);
      clearTimeout(resetTimer);
      button.disabled = true;
      copyStatus.textContent = "";
      try {
        await navigator.clipboard.writeText(command.textContent);
        button.textContent = "Copied";
        button.setAttribute("aria-label", `${copyLabel}: copied`);
        copyStatus.textContent = "Command copied. Paste it into your terminal.";
      } catch {
        const selection = window.getSelection();
        if (selection) {
          const range = document.createRange();
          range.selectNodeContents(command);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        button.textContent = "Copy";
        button.setAttribute("aria-label", copyLabel);
        copyStatus.textContent =
          "Automatic copy is unavailable. Select and copy the command above.";
      } finally {
        button.disabled = false;
        resetTimer = setTimeout(() => {
          button.textContent = "Copy";
          button.setAttribute("aria-label", copyLabel);
        }, 2200);
      }
    });
  });

  document.querySelectorAll(".enhancement").forEach((element) => {
    element.hidden = false;
  });
  selectPanel(categories, coveragePanels, "category", "panel", "network");
  selectPanel(methods, methodPanels, "install", "method", "quick");
  updateFindings();
  document.documentElement.classList.add("enhanced");
})();
