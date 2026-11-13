/* anti-reverse-shield : native defense primitives
 * SPDX-License-Identifier: MIT
 *
 * NOTE: These are defense-in-depth measures. They RAISE the cost of
 * reverse engineering; they do NOT make it impossible. Keep real
 * secrets and trust decisions on the server.
 */
#ifndef ARS_SHIELD_H
#define ARS_SHIELD_H
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- detection ---------------------------------------------------------- */

/* True if a debugger is attached to this process. */
bool ars_is_debugged(void);

/* True if Frida / a dynamic instrumentation toolkit is detected
 * (agent mapping and/or default listening ports 27042/27043). */
bool ars_frida_present(void);

/* True if a hot libc function looks inline-hooked (detour prologue).
 * Catches instrumentation that hides from /proc/self/maps. x86-64 + arm64. */
bool ars_hooks_present(void);

/* True if a timing probe is anomalously slow, implying single-step /
 * breakpoint tracing is active. */
bool ars_timing_anomaly(void);

/* True if a library-injection environment variable is set
 * (LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES, ...). */
bool ars_env_suspicious(void);

/* --- integrity ---------------------------------------------------------- */

/* FNV-1a of this process's own on-disk executable (detects a patched file). */
uint64_t ars_self_file_hash(void);

/* FNV-1a of the in-memory executable segment (detects a RUNTIME patch that
 * leaves the file intact). Returns 0 where unsupported (non-Linux for now). */
uint64_t ars_text_hash(void);

/* --- reaction ----------------------------------------------------------- */

/* Indirect reaction helper. Do NOT exit() at a check — call this with a value
 * your logic depends on. It jitters a short delay and perturbs the value so
 * failure surfaces far from the detection site. */
uint64_t ars_react(uint64_t value);

/* --- aggregate ---------------------------------------------------------- */

enum {
    ARS_FLAG_DEBUGGER  = 1u << 0,
    ARS_FLAG_FRIDA     = 1u << 1,
    ARS_FLAG_HOOK      = 1u << 2,
    ARS_FLAG_TIMING    = 1u << 3,
    ARS_FLAG_ENVINJECT = 1u << 4,
};
/* Run all detectors; returns a bitmask of ARS_FLAG_*. */
unsigned ars_scan(void);

#ifdef __cplusplus
}
#endif
#endif /* ARS_SHIELD_H */
