// SPDX-License-Identifier: MIT
// Detect an open DevTools / attached debugger via the debugger-statement
// timing trick, and react quietly. Run in the renderer.
'use strict';

function startDevtoolsGuard(onDetected) {
  const tick = () => {
    const t0 = performance.now();
    // eslint-disable-next-line no-debugger
    debugger; // pauses only when devtools is open
    if (performance.now() - t0 > 100) {
      onDetected();
    }
  };
  // jittered interval so the check point is not at a fixed cadence
  setInterval(tick, 1000 + Math.floor(Math.random() * 600));
}

if (typeof module !== 'undefined') module.exports = { startDevtoolsGuard };
