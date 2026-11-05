# native — C/C++ defense primitives

Cross-platform (Linux / macOS / Windows) building blocks:

| File | What it does |
|------|--------------|
| `include/shield.h`       | Public API |
| `src/antidebug.c`        | `ars_is_debugged()` — ptrace/TracerPid, sysctl P_TRACED, IsDebuggerPresent + PEB |
| `src/frida_detect.c`     | `ars_frida_present()` — scans `/proc/self/maps` for Frida/gadget |
| `src/antihook.c`         | `ars_hooks_present()` — detects inline-hook detours on hot libc prologues |
| `src/timing.c`           | `ars_timing_anomaly()` — flags single-step/breakpoint tracing via timing |
| `src/integrity.c`        | `ars_self_file_hash()` — FNV-1a over the on-disk executable (patched-file tripwire) |
| `src/memhash.c`          | `ars_text_hash()` — FNV-1a over the in-memory exec segment (runtime-patch tripwire) |
| `src/react.c`            | `ars_react()` — indirect reaction (delay + value perturbation), never `exit()` |
| `include/obfstr.hpp`     | Compile-time XOR strings (plaintext never hits the binary) |
| `examples/demo.c`        | Runnable example exercising the whole API |

## Build
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/ars_demo
```
Verified to build and run on Linux/macOS/Windows via CI (`.github/workflows/native-build.yml`).

## Usage pattern (important)
- **Scatter** checks across many call sites; never put them all in one function.
- **React with `ars_react()`**, not an immediate `exit()`. An instant exit hands
  the analyst the exact address of your check.
- Bake the expected `ars_self_file_hash()` **and** `ars_text_hash()` into the
  build and compare at runtime — the first catches a patched file, the second a
  runtime (in-memory) patch that leaves the file intact.
- For strings: `char b[64]; const char* s = ARS_OBF("secret").decrypt(b); /* use */ memset(b,0,sizeof b);`

## Hardening at build time (biggest win per effort)
- Strip symbols: `strip --strip-all`
- LLVM obfuscation passes: **OLLVM / o-mvll** (control-flow flattening, bogus flow)
- Commercial virtualization for high-value binaries: VMProtect / Themida

See [`../docs/PRINCIPLES.md`](../docs/PRINCIPLES.md) for exactly how each check works.
