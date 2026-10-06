// WebGPU heat effects. Pure decoration: the page is complete without them.
// Loads the shader library only when the browser has WebGPU and motion is welcome.

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const canvases = [...document.querySelectorAll("canvas[data-fx]")];

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const clamp01 = (n) => Math.max(0, Math.min(1, n));

// Score (0-100) → how hot each effect runs.
function heat(score) {
  const t = clamp01(score / 100);
  return {
    t,
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

// Each effect gets a canvas and a function that returns its layer stack.
const PRESETS = {
  // Cursor smoke and rising embers behind the hero.
  embers: () => ({
    components: [
      {
        type: "SmokeFlow",
        id: "smoke",
        props: {
          colorA: css("--fx-smoke-fresh"),
          colorB: css("--fx-smoke-aged"),
          intensity: 0.9,
          emitRadius: 0.06,
          momentum: 18,
          dissipation: 0.9,
          detail: 18,
          gravity: -1.6,
          colorDecay: 0.9,
        },
      },
      {
        type: "FloatingParticles",
        id: "embers",
        props: {
          particleColor: css("--fx-ember"),
          count: 380,
          particleSize: 1.2,
          softness: 0.55,
          speed: 0.18,
          angle: 90,
          angleVariance: 25,
          speedVariance: 0.5,
          randomness: 0.4,
          twinkle: 0.8,
          cursorStrength: 0.35,
        },
      },
    ],
  }),

  // Thermal-camera view whose temperature follows a score.
  thermal: (canvas) => {
    const h = heat(Number(canvas.dataset.score) || 0);
    return {
      components: [
        {
          type: "Heatmap",
          id: "heat",
          props: { ...h.heatmap, shape: JSON.stringify({ type: "metaballs3D" }) },
        },
        { type: "Glitch", id: "glitch", props: { ...h.glitch, speed: 1.4, rgbShift: 6, scanlineIntensity: 0.25 } },
        { type: "FilmGrain", props: { strength: 0.18, animated: true } },
      ],
    };
  },

  // The 404 page: nothing here but smoke.
  smoke: () => ({
    components: [
      {
        type: "SmokeFlow",
        props: {
          colorA: css("--fx-smoke-fresh"),
          colorB: css("--fx-smoke-aged"),
          intensity: 1.3,
          emitRadius: 0.09,
          dissipation: 0.4,
          detail: 28,
          gravity: -2.4,
          colorDecay: 0.6,
        },
      },
    ],
  }),
};

async function boot() {
  if (!canvases.length || reduceMotion.matches || !("gpu" in navigator)) return;

  let lib;
  try {
    lib = await import("./vendor/shaders-4.0.0.js");
    if (!(await lib.isWebGPUSupported())) return;
  } catch {
    return;
  }

  const gpu = await lib.createSharedDevice().catch(() => undefined);
  const instances = new Map();

  async function mount(canvas) {
    const preset = PRESETS[canvas.dataset.fx];
    if (!preset) return;
    try {
      const instance = await lib.createShader(canvas, preset(canvas), {
        disableTelemetry: true,
        gpu,
        onReady: () => canvas.classList.add("fx-ready"),
        // Recoverable GPU resets also land here; hide the canvas only once it has given up.
        onError: () =>
          setTimeout(() => {
            const instance = instances.get(canvas);
            if (!instance || instance.getFailureReason()) canvas.classList.remove("fx-ready");
          }, 0),
      });
      instances.set(canvas, instance);
    } catch {
      canvas.classList.remove("fx-ready");
    }
  }

  await Promise.all(canvases.map(mount));

  // The hero backdrop fades out as the hero scrolls away, then stops drawing.
  const backdrop = canvases.find((c) => c.classList.contains("fx-hero"));
  const hero = document.querySelector(".hero");
  if (backdrop && hero) {
    let paused = false;
    const onScroll = () => {
      const instance = instances.get(backdrop);
      if (!instance) return;
      const fade = clamp01(1 - window.scrollY / Math.max(1, hero.offsetTop + hero.offsetHeight * 0.8));
      backdrop.style.setProperty("--fx-hero-opacity", fade.toFixed(3));
      if (fade === 0 && !paused) {
        instance.pause();
        paused = true;
      } else if (fade > 0 && paused) {
        instance.resume();
        paused = false;
      }
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  // Score changes from the simulator or the report viewer heat up the thermal views.
  document.addEventListener("iscooked:score", (event) => {
    const h = heat(event.detail.score);
    canvases
      .filter((c) => c.dataset.fx === "thermal" && (!event.detail.target || c.closest(event.detail.target)))
      .forEach((canvas) => {
        canvas.dataset.score = String(event.detail.score);
        const instance = instances.get(canvas);
        if (!instance) return;
        instance.update("heat", h.heatmap);
        instance.update("glitch", h.glitch);
      });
  });

  // Smoke colors follow the light/dark theme.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    instances.forEach((instance, canvas) => {
      if (canvas.dataset.fx === "thermal") return;
      try {
        instance.update("smoke", { colorA: css("--fx-smoke-fresh"), colorB: css("--fx-smoke-aged") });
        instance.update("embers", { particleColor: css("--fx-ember") });
      } catch {
        /* the 404 smoke has no ids; it keeps its colors */
      }
    });
  });

  reduceMotion.addEventListener("change", () => {
    if (reduceMotion.matches) {
      instances.forEach((instance, canvas) => {
        instance.destroy();
        canvas.classList.remove("fx-ready");
      });
      instances.clear();
    }
  });
}

boot();
