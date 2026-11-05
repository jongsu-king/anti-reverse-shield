# anti-reverse-shield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/1446439180.svg)](https://zenodo.org/badge/latestdoi/1446439180)
[![native-build](https://github.com/jongsu-king/anti-reverse-shield/actions/workflows/native-build.yml/badge.svg)](.github/workflows/native-build.yml)

Defense-in-depth building blocks against automated reverse-engineering tooling
(the Ghidra/IDA + Frida + MITM-proxy pipeline that AI RE agents automate).

> The DOI badge resolves once the repository is archived on Zenodo — see
> [Citation & DOI](#citation--doi). Until the first Zenodo release it 404s; that
> is expected, not a broken link.

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
| Native C/C++ (Linux/macOS/Win) | [`native/`](native)   | anti-debug, Frida detection, **inline-hook detection**, **timing-anomaly check**, on-disk **and in-memory** integrity hashes, compile-time string encryption, **indirect-reaction helper** |
| Electron / JavaScript          | [`electron/`](electron) | V8 bytecode, obfuscation, Electron fuses, DevTools guard |
| Android (APK)                  | [`android/`](android)  | debugger/root/emulator/Frida detection, signature check, cert pinning, R8 rules, **native JNI bridge** |
| .NET (C#)                       | [`dotnet/`](dotnet)    | anti-debug, self-integrity hash, ConfuserEx config |
| Server (reference)             | [`server/`](server)    | **HMAC + nonce + timestamp** request verification — the durable boundary |

Full write-up with the threat model and per-tool mapping: [`docs/guide.md`](docs/guide.md).

**Read this too:** every technique here can be bypassed — see [`docs/WEAKNESSES.md`](docs/WEAKNESSES.md) for exactly how, and what residual value each one keeps.

**Why it's built this way:** [`docs/REA-anti-anti.md`](docs/REA-anti-anti.md) dissects how REA-style tools analyze (static extraction → runtime capture → AI reconstruction) and maps each defense to the exact analyzer it starves.

**How each defense actually works (English deep-dive):** [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md) explains the mechanism of every technique — ptrace/PEB/`P_TRACED`, Frida mapping detection, FNV-1a self-hashing, `constexpr` string encryption, control-flow flattening, V8 bytecode, Electron fuses, SPKI certificate pinning, and server-side HMAC — at the level of *why it works and against what*.

### Documentation map
| Doc | Language | What it is |
|-----|----------|-----------|
| [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md)       | English | Mechanism / internals of every defense |
| [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md)           | 한국어 + ASCII | Mechanism diagrams drawn in text (hook detours, pin abort, CFG flattening, disk-vs-memory hash, evidence funnel) |
| [`docs/guide.md`](docs/guide.md)                 | 한국어  | Conceptual, layered-defense guide |
| [`docs/REA-anti-anti.md`](docs/REA-anti-anti.md) | 한국어  | REA pipeline dissection + per-analyzer counter-mapping |
| [`docs/WEAKNESSES.md`](docs/WEAKNESSES.md)        | 한국어  | How each defense is bypassed + residual value |

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

## Citation & DOI

Citation metadata lives in [`CITATION.cff`](CITATION.cff) (GitHub shows a
"Cite this repository" button from it). To mint a **real, resolvable DOI**:

1. Sign in to <https://zenodo.org> with your GitHub account.
2. In Zenodo → **GitHub**, flip the switch **on** for `anti-reverse-shield`.
3. Create a GitHub release (e.g. `v0.2.0`). Zenodo archives it and mints a DOI.
4. Copy the DOI into `CITATION.cff` (uncomment the `doi:` line) — the badge above
   then resolves automatically.

A DOI cannot be self-assigned; it is issued by a registration agency (Zenodo
uses DataCite). The badge and metadata here are wired so that step 3 is the only
remaining action.

## License

MIT — see [LICENSE](LICENSE). Use only on software you own or are authorized to protect.
