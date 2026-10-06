// Hover chrome, lean, and thermal views. Pure decoration: the page is complete without them.
// Tilt runs everywhere motion is welcome. The shader library loads only with WebGPU.

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const clamp01 = (n) => Math.max(0, Math.min(1, n));

const CHROME_TARGETS = ".chrome-wrap, .button-primary, .button-outline, .oneliner .copy-button";
const chromeTargets = [...document.querySelectorAll(CHROME_TARGETS)];
const thermals = [...document.querySelectorAll("canvas[data-fx='thermal']")];

// ─── Lean ───────────────────────────────────────────────
// Elements tilt toward the cursor. Big panels lean more than buttons.
function lean(element, event) {
  const rect = element.getBoundingClientRect();
  const x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  const y = ((event.clientY - rect.top) / rect.height) * 2 - 1;
  const max = element.classList.contains("chrome-wrap") ? 6 : 10;
  element.style.setProperty("--lean-x", `${(-y * max).toFixed(2)}deg`);
  element.style.setProperty("--lean-y", `${(x * max).toFixed(2)}deg`);
  element.style.setProperty("--glint-x", `${((x + 1) * 50).toFixed(1)}%`);
  element.style.setProperty("--glint-y", `${((y + 1) * 50).toFixed(1)}%`);
  return x;
}

function settle(element) {
  element.style.setProperty("--lean-x", "0deg");
  element.style.setProperty("--lean-y", "0deg");
}

// ─── Shader helpers ─────────────────────────────────────
function heat(score) {
  const t = clamp01(score / 100);
  return {
    heatmap: {
      scale: 0.55 + 0.7 * t,
      speed: 0.25 + 2.4 * t,
      innerGlow: 0.12 + 0.65 * t,
      outerGlow: 0.08 + 0.55 * t,
      contour: 0.35 + 0.4 * t,
    },
    glitch: { intensity: t >= 0.7 ? 0.12 + 0.5 * (t - 0.7) : 0 },
  };
}

function thermalPreset(canvas) {
  const h = heat(Number(canvas.dataset.score) || 0);
  return {
    components: [
      { type: "Heatmap", id: "heat", props: { ...h.heatmap, shape: JSON.stringify({ type: "metaballs3D" }) } },
      { type: "Glitch", id: "glitch", props: { ...h.glitch, speed: 1.4, rgbShift: 6, scanlineIntensity: 0.25 } },
      { type: "FilmGrain", props: { strength: 0.18, animated: true } },
    ],
  };
}

// A rounded rectangle that fills the canvas. The shape field is sized to the short side.
// Layout size, not the bounding box: the element may be tilted.
// `bleedPx` pushes the shape's bevel past the canvas edge so only the polished face shows.
function chromeShape(canvas, radiusPx, bleedPx = 0) {
  const width = canvas.offsetWidth + 2 * bleedPx;
  const height = canvas.offsetHeight + 2 * bleedPx;
  const short = Math.max(1, Math.min(canvas.offsetWidth, canvas.offsetHeight));
  return JSON.stringify({
    type: "roundedRectSDF",
    radius: (0.5 * width) / short - 0.002,
    height: (0.5 * height) / short - 0.002,
    rounding: Math.min(0.5, radiusPx / short),
  });
}

function chromeProps(canvas, kind) {
  const bezel = kind === "bezel";
  return {
    tint: css(bezel ? "--chrome-bezel" : "--chrome-tint"),
    warmColor: css("--chrome-warm"),
    coolColor: css("--chrome-cool"),
    shape: chromeShape(canvas, bezel ? 20 : 4, bezel ? 40 : 0),
    bevelWidth: bezel ? 0.035 : 0.2,
    bevelShape: 1,
    curvature: bezel ? 0.9 : 0.08,
    waviness: 0.06,
    softness: bezel ? 0.25 : 0.45,
    spectral: bezel ? 1.2 : 0.6,
    shadows: bezel ? 0.35 : 0.7,
    environment: bezel ? 1.15 : 0.8,
    speed: 0,
    envRotation: 0,
  };
}

async function loadLibrary() {
  if (!("gpu" in navigator)) return null;
  try {
    const lib = await import("./vendor/shaders-4.0.0.js");
    if (!(await lib.isWebGPUSupported())) return null;
    const gpu = await lib.createSharedDevice().catch(() => undefined);
    return { lib, gpu };
  } catch {
    return null;
  }
}

async function boot() {
  if (reduceMotion.matches) return;

  // Lean works without WebGPU.
  if (finePointer.matches) {
    chromeTargets.forEach((element) => {
      element.classList.add("leans");
      element.addEventListener("pointermove", (event) => lean(element, event));
      element.addEventListener("pointerleave", () => settle(element));
    });
  }

  if (!chromeTargets.length && !thermals.length) return;
  const loaded = await loadLibrary();
  if (!loaded) return;
  const { lib, gpu } = loaded;
  const options = (canvas) => ({
    disableTelemetry: true,
    gpu,
    onReady: () => canvas.classList.add("fx-ready"),
    onError: () =>
      setTimeout(() => {
        const instance = instances.get(canvas);
        if (!instance || instance.getFailureReason()) canvas.classList.remove("fx-ready");
      }, 0),
  });
  const instances = new Map();

  // ─── Thermal views ──────────────────────────────────
  await Promise.all(
    thermals.map(async (canvas) => {
      try {
        instances.set(canvas, await lib.createShader(canvas, thermalPreset(canvas), options(canvas)));
      } catch {
        /* decorative */
      }
    }),
  );
  document.addEventListener("iscooked:score", (event) => {
    const h = heat(event.detail.score);
    thermals
      .filter((c) => !event.detail.target || c.closest(event.detail.target))
      .forEach((canvas) => {
        canvas.dataset.score = String(event.detail.score);
        const instance = instances.get(canvas);
        if (!instance) return;
        instance.update("heat", h.heatmap);
        instance.update("glitch", h.glitch);
      });
  });

  // ─── Chrome on hover ────────────────────────────────
  // Each target gets its skin on first hover, then pauses while the cursor is away.
  if (!finePointer.matches) return;
  chromeTargets.forEach((element) => {
    const kind = element.classList.contains("chrome-wrap") ? "bezel" : "button";
    let canvas = null;
    let instance = null;
    let mounting = null;
    let pauseTimer = 0;

    async function mount() {
      canvas = document.createElement("canvas");
      canvas.className = `chrome-skin chrome-${kind}`;
      canvas.setAttribute("aria-hidden", "true");
      element.prepend(canvas);
      try {
        instance = await lib.createShader(
          canvas,
          { components: [{ type: "Chrome", id: "chrome", props: chromeProps(canvas, kind) }] },
          { ...options(canvas), observeElement: true },
        );
        instances.set(canvas, instance);
        let firstResize = true;
        new ResizeObserver(() => {
          if (firstResize) return void (firstResize = false);
          instance.update("chrome", { shape: chromeShape(canvas, kind === "bezel" ? 20 : 4, kind === "bezel" ? 40 : 0) });
        }).observe(canvas);
      } catch {
        canvas.remove();
        canvas = null;
      }
    }

    element.addEventListener("pointerenter", async () => {
      clearTimeout(pauseTimer);
      if (!canvas) mounting = mounting || mount();
      await mounting;
      instance?.resume();
      element.classList.add("chromed");
    });
    element.addEventListener("pointermove", (event) => {
      if (!instance) return;
      const rect = element.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      instance.update("chrome", { envRotation: x * 70 });
    });
    element.addEventListener("pointerleave", () => {
      element.classList.remove("chromed");
      pauseTimer = setTimeout(() => instance?.pause(), 700);
    });
  });

  // Chrome follows the light/dark theme.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    instances.forEach((instance, canvas) => {
      if (!canvas.classList.contains("chrome-skin")) return;
      const bezel = canvas.classList.contains("chrome-bezel");
      instance.update("chrome", {
        tint: css(bezel ? "--chrome-bezel" : "--chrome-tint"),
        warmColor: css("--chrome-warm"),
        coolColor: css("--chrome-cool"),
      });
    });
  });
}

boot();
