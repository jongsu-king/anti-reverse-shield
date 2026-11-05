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

/* Returns true if a debugger is attached to this process. */
bool ars_is_debugged(void);

/* Returns true if Frida / a dynamic instrumentation toolkit is detected. */
bool ars_frida_present(void);

/* FNV-1a hash of this process's own on-disk executable.
 * Compare against a value baked in at release time to detect patching.
 * Returns 0 on failure to read the executable. */
uint64_t ars_self_file_hash(void);

/* Convenience: run all checks. Returns a bitmask of ARS_FLAG_* set. */
enum {
    ARS_FLAG_DEBUGGER = 1u << 0,
    ARS_FLAG_FRIDA    = 1u << 1,
};
unsigned ars_scan(void);

#ifdef __cplusplus
}
#endif
#endif /* ARS_SHIELD_H */
