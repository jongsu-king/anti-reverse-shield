// SPDX-License-Identifier: MIT
package shield

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.security.MessageDigest

/**
 * Kotlin-level checks are easy to patch out. Treat them as ONE layer and put
 * the decisive checks in native (.so via NDK) using the C code in ../native.
 * React with delay / degraded behaviour, not an instant finish().
 */
object SecurityChecks {

    fun isDebuggerAttached(): Boolean =
        Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    fun isRooted(): Boolean {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/su", "/su/bin/su"
        )
        if (suPaths.any { File(it).exists() }) return true
        return Build.TAGS?.contains("test-keys") == true
    }

    fun isEmulator(): Boolean = with(Build) {
        FINGERPRINT.startsWith("generic") || FINGERPRINT.contains("vbox") ||
        MODEL.contains("Emulator") || MODEL.contains("sdk") ||
        MANUFACTURER.contains("Genymotion") || PRODUCT.contains("sdk_gphone") ||
        HARDWARE.contains("goldfish") || HARDWARE.contains("ranchu")
    }

    fun isFridaPresent(): Boolean {
        runCatching {
            File("/proc/self/maps").forEachLine { line ->
                if (line.contains("frida") || line.contains("gum-js") ||
                    line.contains("gadget")) return true
            }
        }
        return false
    }

    /** Detects re-signing / re-packaging by comparing the signer's SHA-256. */
    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    fun signatureMatches(ctx: Context, expectedSha256: String): Boolean = runCatching {
        val sigs = ctx.packageManager
            .getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
            .signatures ?: return false
        val digest = MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray())
        digest.joinToString("") { "%02x".format(it) }
            .equals(expectedSha256, ignoreCase = true)
    }.getOrDefault(false)
}
