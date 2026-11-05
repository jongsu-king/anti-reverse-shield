# Principles & Internals — how each defense actually works

> English deep-dive into the *mechanism* behind every module. For the
> conceptual guide see [`guide.md`](guide.md); for how each defense is
> defeated see [`WEAKNESSES.md`](WEAKNESSES.md); for the REA-specific mapping
> see [`REA-anti-anti.md`](REA-anti-anti.md).

Each technique below is explained at the level of *why it works and against
what exactly*, so you can reason about residual risk instead of cargo-culting.

---

## 1. Anti-debugging — detecting an attached tracer

### 1.1 Linux: `ptrace(PTRACE_TRACEME)` and `TracerPid`
On Linux a process can be traced by **at most one** tracer at a time. The
kernel stores the tracer's PID in the task's `ptrace` relationship.

- **Self-trace probe:** calling `ptrace(PTRACE_TRACEME, 0, 0, 0)` asks "make my
  parent my tracer." If a debugger (gdb, strace, REA's pwndbg) is **already**
  attached, there is already a tracer, so the call returns `-1`/`EPERM`. That
  failure is the signal. The weakness: a debugger can intercept the syscall, and
  the probe itself changes state, so we prefer reading `TracerPid` first.
- **`/proc/self/status` → `TracerPid:`** The kernel exposes the current tracer's
  PID here. `0` means no tracer; non-zero is the debugger's PID. This is a pure
  read — it does not perturb process state, which is why `antidebug.c` checks it
  before the ptrace probe.

### 1.2 macOS: `sysctl` + `P_TRACED`
Darwin has no `/proc`. Instead you ask the kernel for your own `kinfo_proc`
via `sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()})` and test the
`p_flag` field for the `P_TRACED` bit, which the kernel sets while a debugger
is attached. This is the canonical, documented check used by Apple's own tools.

### 1.3 Windows: `BeingDebugged`, `NtGlobalFlag`, remote checks
- `IsDebuggerPresent()` simply reads `PEB->BeingDebugged`. Easy to call, easy to
  defeat (an attacker flips the byte), so we also read the **PEB directly** via
  the `gs`/`fs` segment (`__readgsqword(0x60)` on x64) to bypass a hooked
  `IsDebuggerPresent`.
- `CheckRemoteDebuggerPresent()` asks the kernel whether a debugger is attached
  to a given process handle — catches debuggers that do not set the local flag.
- Stronger variants (not shipped, to stay portable): `NtGlobalFlag` heap flags,
  heap tail-check patterns, and hardware-breakpoint detection via `GetThreadContext`
  reading `Dr0–Dr7`.

### 1.4 The golden rule: react indirectly
Every check above yields a boolean. If you branch `if (detected) exit()`, the
attacker sets a breakpoint on `exit`, walks back one frame, and NOPs the branch.
So the library's guidance is to **scatter** checks and **react with latency or
state corruption** (return subtly wrong results minutes later), which forces the
attacker to understand *semantics*, not just find one branch.

---

## 2. Anti-instrumentation — detecting Frida and inline hooks

### 2.1 How Frida gets in
Frida injects an agent (`frida-agent`, `gum-js-loop` thread) into the target,
either by `ptrace`-based injection into a running process or by linking a
**gadget** library into the app. Either way, the agent's shared object is mapped
into the process address space and shows up in the memory map.

### 2.2 The `/proc/self/maps` scan
`frida_detect.c` reads `/proc/self/maps` and looks for the agent's footprint:
`frida`, `gum-js`, `gadget`, `linjector`. If the agent is mapped, its name is
in the maps. **Weakness:** the gadget can be renamed and Frida can hook the very
`fopen`/`read` used to read `maps` and filter itself out — hence the "residual
hardening" column in the docs calls for cross-checking from native code and
detecting hooks on `fopen` itself.

### 2.3 Inline-hook / PLT-GOT detection (the next layer)
A more robust check (documented as a strengthening path) is to checksum your own
`.plt`/`.got` and the first bytes of hot libc functions. An inline hook
overwrites a function prologue with a `jmp` to the detour; comparing the live
bytes against a known-good hash reveals the trampoline even when the agent hides
from `maps`.

---

## 3. Integrity — self-checksums and why disk ≠ memory

`integrity.c` computes an **FNV-1a 64-bit** hash over the process's own
executable file (found via `/proc/self/exe`, `_NSGetExecutablePath`, or
`GetModuleFileNameA`). FNV-1a is used for speed and simplicity — this is a
tamper tripwire, not a cryptographic MAC.

**The critical nuance:** hashing the file on disk detects a *patched binary on
disk* (a cracked `.exe` shipped to others). It does **not** detect an attacker
who loads the clean binary and patches it **in memory** under a debugger — the
file is untouched. Catching that requires hashing the in-memory `.text` segment,
which is harder because you must (a) know the segment bounds at runtime, and
(b) exclude relocated/ASLR-adjusted bytes or hash before relocation. Even then,
the attacker can hook the hash function or patch the comparison — so the expected
value must be obfuscated and the comparison scattered.

---

## 4. Compile-time string encryption — defeating `strings`, not memory

`obfstr.hpp` uses a C++ `constexpr` constructor to XOR each character at
**compile time**. Because the transformation happens during compilation, the
plaintext literal is never emitted into the `.rodata` section — only the XORed
bytes are. That is why `strings mybinary | grep api.example.com` returns nothing
(verified in this repo: zero hits).

**Mechanism boundary:** the key is a compile-time constant embedded in the
binary, and decryption happens at runtime into a stack buffer. So the protection
holds only against *static* extraction. An attacker who sets a breakpoint right
after `decrypt()` reads the plaintext straight from the stack. The mitigation is
**decrypt → use → `memset` wipe** in the tightest possible window, plus
per-string keys so one recovered key doesn't unlock everything.

---

## 5. Control-flow flattening & opaque predicates (OLLVM)

Decompilers reconstruct a function's control-flow graph (CFG) from its branch
structure, then recover `if`/`while`/`for` from that graph. **Flattening**
destroys the recoverable shape:

- Every basic block is pulled into a single `switch` dispatched by a **state
  variable**. The original fall-through/branch edges become `state = N; goto
  dispatcher;`. The decompiler now sees one giant dispatcher loop instead of
  nested conditionals, and the human-readable structure is gone.
- **Opaque predicates** add branches whose outcome is known to the compiler but
  not obvious to an analyzer (e.g. `(x*x) >= 0` is always true), inflating the
  graph with dead edges.

**Why it only raises cost:** the semantics are unchanged, so dynamic tracing and
purpose-built deobfuscators (symbolic execution to collapse opaque predicates,
state-variable recovery to unflatten) can reverse it — and an AI agent can be
pointed at those tools. It buys time, not secrecy.

---

## 6. Electron: V8 bytecode and fuses

### 6.1 bytenode / V8 bytecode
V8 compiles JS to **Ignition bytecode** and can serialize that compiled form
(`vm.Script` `cachedData`). `bytenode` ships the `.jsc` (bytecode) and discards
the `.js`, so `asar` extraction yields bytecode, not source. **Boundary:** this
is obfuscation, not encryption — V8 bytecode disassemblers exist, and the
bytecode is version-locked to the exact V8 build you compiled with.

### 6.2 Electron fuses — closing the "run as node" door
An Electron binary is also a Node runtime. By default an attacker can set
`ELECTRON_RUN_AS_NODE=1` (or pass `--inspect`) to launch your app as plain Node
and dump every module from memory. The fuses `RunAsNode:false` and
`EnableNodeCliInspectArguments:false` **compile these capabilities out of the
binary**, so the dump path is gone. `EnableEmbeddedAsarIntegrityValidation`
makes the loader verify the asar's header hash, and `OnlyLoadAppFromAsar`
forbids loading code from outside the (hash-checked) archive.

---

## 7. Certificate pinning — defeating the MITM proxy (REA's mitmdump)

A normal TLS client trusts any certificate that chains to a trusted CA. A MITM
proxy (mitmproxy/mitmdump, which REA uses for network capture) installs its own
CA on the device, then presents a freshly minted cert for `api.example.com`
signed by that CA — the client validates it and the proxy sees plaintext.

**Pinning** adds a second check: after normal chain validation, the client
compares the server's **SubjectPublicKeyInfo (SPKI)** hash against a hash
**baked into the app**. The proxy's substitute cert has a different public key,
so its SPKI hash doesn't match the pin, and the connection is aborted — the
capture yields TLS errors instead of plaintext. That is exactly the "turn
plaintext into garbage" outcome in the REA mapping.

**Boundary / why a backup pin:** if you pin a leaf cert and rotate it, the app
breaks; so pin the SPKI (stable across renewals) and ship a **backup pin**. On a
rooted device, a universal Frida script hooks the validation callback and
returns "valid" regardless — which is why pinning must be paired with
payload-level encryption + HMAC request signing so the body is useless even if
the pin is stripped.

---

## 8. Android R8 / ConfuserEx — what "obfuscation" buys

- **R8 (Android):** renames classes/methods to `a.a.a`, shrinks unused code, and
  optimizes. It raises the cost of *reading* JADX output but leaves the logic
  intact and fully recoverable. `repackageclasses ''` collapses the package tree
  so the structure no longer telegraphs intent.
- **ConfuserEx (.NET) anti-tamper:** encrypts method bodies at protect time and
  decrypts them at runtime in the module constructor, which also checksums the
  module; a patched assembly fails the checksum and the decryptor produces
  garbage. **Boundary:** public unpackers (de4dot-family) and runtime dumping at
  the moment of decryption defeat it — it is cost, not a vault.

---

## 9. The only durable layer — server-side authority + economics

Every technique above is **advisory**: it runs on hardware the attacker
controls, so it can be observed, patched, or lied to. The two defenses that do
**not** depend on client trust:

1. **Keep the decision on the server.** A license check that returns a
   server-signed capability token (short-lived, scoped) cannot be NOP-ed,
   because the client has nothing to NOP — the answer lives across the network.
   Pair requests with **HMAC(body ‖ nonce ‖ timestamp)** so they can't be
   forged or replayed, and encrypt sensitive fields end-to-end so a stripped pin
   still yields ciphertext.
2. **Remove the incentive.** If cracking the client grants nothing of value
   (because the value is a server-rendered result, a SaaS feature, or
   server-held data), the economic motive to reverse-engineer evaporates. This
   is the strongest "anti-anti" of all: it makes REA's output *correct but
   useless*.
