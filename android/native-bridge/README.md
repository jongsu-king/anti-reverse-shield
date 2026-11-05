# android/native-bridge — move the decisive checks into native

Kotlin/Java checks are patched out in smali in minutes. This bridge runs the
detectors from [`../../native`](../../native) inside a `.so` via JNI, so a
bypass requires defeating native code (which also carries anti-debug, inline-
hook detection, and in-memory integrity).

- `shield_jni.c`   — JNI entry points calling `ars_scan()` / `ars_text_hash()`
- `NativeBridge.kt` — Kotlin `external` declarations + flag constants

Build `libshield.so` with the NDK (link the `ars_shield` static lib from
`native/`), place it under `src/main/jniLibs/<abi>/`, and gate sensitive paths
on `NativeBridge.isInstrumented()` — reacting indirectly, never with an instant
`finish()`.
