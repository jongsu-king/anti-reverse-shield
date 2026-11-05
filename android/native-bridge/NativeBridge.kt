// SPDX-License-Identifier: MIT
package shield

/**
 * Kotlin side of the JNI bridge. The real detection runs in libshield.so
 * (native/), so an attacker cannot simply patch Kotlin/smali to bypass it —
 * they must defeat the native code, which also carries anti-debug + integrity.
 *
 * Bitmask matches ARS_FLAG_* in native/include/shield.h.
 */
object NativeBridge {
    init { System.loadLibrary("shield") }

    external fun scan(): Int        // bitmask of ARS_FLAG_*
    external fun textHash(): Long   // in-memory .text FNV-1a

    const val FLAG_DEBUGGER = 1
    const val FLAG_FRIDA    = 2
    const val FLAG_HOOK     = 4
    const val FLAG_TIMING   = 8

    fun isInstrumented(): Boolean = scan() != 0
}
