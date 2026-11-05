# anti-reverse-shield

Defense-in-depth building blocks against automated reverse-engineering tooling
(the Ghidra/IDA + Frida + MITM-proxy pipeline that AI RE agents automate).

> ### Honest scope
> **There is no such thing as perfect/unbreakable client-side protection.**
> Code that runs on a machine you do not control can always, eventually, be
> analyzed. These modules **raise the cost** of analysis and tampering — enough
> to deter casual and automated attackers. They are **not** a security boundary.
>
> **The real boundary is your server.** Keep licensing, payment, secrets, and
> decisive trust checks server-side. Use this library only as a supplementary layer.

## What's inside

| Platform | Directory | Covers |
|----------|-----------|--------|
| Native C/C++ (Linux/macOS/Win) | [`native/`](native)   | anti-debug, Frida detection, self-integrity hash, compile-time string encryption |
| Electron / JavaScript          | [`electron/`](electron) | V8 bytecode, obfuscation, Electron fuses, DevTools guard |
| Android (APK)                  | [`android/`](android)  | debugger/root/emulator/Frida detection, signature check, cert pinning, R8 rules |
| .NET (C#)                       | [`dotnet/`](dotnet)    | anti-debug, self-integrity hash, ConfuserEx config |

Full write-up with the threat model and per-tool mapping: [`docs/guide.md`](docs/guide.md).

**Read this too:** every technique here can be bypassed — see [`docs/WEAKNESSES.md`](docs/WEAKNESSES.md) for exactly how, and what residual value each one keeps.

**Why it's built this way:** [`docs/REA-anti-anti.md`](docs/REA-anti-anti.md) dissects how REA-style tools analyze (static extraction → runtime capture → AI reconstruction) and maps each defense to the exact analyzer it starves.

## Design rules (apply to every layer)
1. **Combine layers.** Static obfuscation alone falls to runtime capture; anti-debug
   alone falls to static patching. Use static + dynamic + integrity together.
2. **Scatter the checks.** Many call sites, not one `check()` function.
3. **React indirectly.** Delay, corrupt state, or fail later — never `exit()` at the
   check. An instant exit pinpoints the check for the attacker.
4. **Rotate / back up pins and keys.** A bricked app from an expired pin is a worse
   outcome than the threat.

## Quick start (native)
```bash
cd native
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/ars_demo
```

## License
MIT — see [LICENSE](LICENSE). Use only on software you own or are authorized to protect.
