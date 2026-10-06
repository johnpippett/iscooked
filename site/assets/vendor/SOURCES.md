# Vendored libraries

- `shaders-4.0.0.js` is `shaders@4.0.0/dist/js/bundle.js` from npm
  (https://github.com/shader-effects-inc/shaders). MIT, see `shaders-LICENSE.txt`.
  The site loads it only on browsers with WebGPU and without reduced motion.
  Every call passes `disableTelemetry: true`. The site CSP also sets
  `connect-src 'self'`, so the library cannot reach shaders.com.
