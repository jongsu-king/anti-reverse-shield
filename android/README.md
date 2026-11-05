# android — APK hardening

| File | Purpose |
|------|---------|
| `SecurityChecks.kt`            | debugger / root / emulator / Frida / re-signing detection |
| `network_security_config.xml`  | block cleartext + certificate pinning (defeats MITM proxy) |
| `proguard-rules.pro`           | R8 name obfuscation + log stripping |

## Layering
- R8 (free) only renames. For string + control-flow obfuscation use a commercial
  tool (DexGuard) or move the logic to native.
- **Put the real checks in native** (`../native`, built with the NDK) and call
  via JNI. Kotlin checks alone are trivially patched in smali.
- Pinning: compute the SPKI pin with
  `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`
