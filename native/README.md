# native — C/C++ defense primitives

Cross-platform (Linux / macOS / Windows) building blocks:

| File | What it does |
|------|--------------|
| `include/shield.h`       | Public API |
| `src/antidebug.c`        | `ars_is_debugged()` — ptrace/TracerPid, sysctl P_TRACED, IsDebuggerPresent + PEB |
| `src/frida_detect.c`     | `ars_frida_present()` — scans `/proc/self/maps` for Frida/gadget |
| `src/integrity.c`        | `ars_self_file_hash()` — FNV-1a over the running executable (tamper check) |
| `include/obfstr.hpp`     | Compile-time XOR strings (plaintext never hits the binary) |
| `examples/demo.c`        | Runnable example |

## Build
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/ars_demo
```

## Usage pattern (important)
- **Scatter** checks across many call sites; never put them all in one function.
- **React with delay / corruption**, not an immediate `exit()`. An instant exit
  hands the analyst the exact address of your check.
- Bake the expected `ars_self_file_hash()` into the build and compare at runtime.
- For strings: `char b[64]; const char* s = ARS_OBF("secret").decrypt(b); /* use */ memset(b,0,sizeof b);`

## Hardening at build time (biggest win per effort)
- Strip symbols: `strip --strip-all`
- LLVM obfuscation passes: **OLLVM / o-mvll** (control-flow flattening, bogus flow)
- Commercial virtualization for high-value binaries: VMProtect / Themida
