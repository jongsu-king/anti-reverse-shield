# dotnet — .NET (C#) hardening

| File | Purpose |
|------|---------|
| `SecurityGuard.cs` | runtime anti-debug (`Debugger.IsAttached` + `CheckRemoteDebuggerPresent`) |
| `Integrity.cs`     | self-assembly SHA-256 tamper check |
| `confuser.crproj`  | ConfuserEx config (anti-tamper + constants + ctrl flow + rename) |

## Notes
- .NET ships IL, which is the easiest target of all. Obfuscation only slows it.
- For anything that matters: move logic server-side, or isolate it in a native
  C/C++ DLL (see `../native`) and call it via P/Invoke.
- `PublishAot` (NativeAOT) removes IL entirely and is the strongest built-in option;
  note that `Assembly.Location` is empty under single-file/AOT, so anchor
  `Integrity` on a shipped data file instead.
