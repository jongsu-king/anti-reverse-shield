/* SPDX-License-Identifier: MIT
 * Minimal demo. Build with the provided CMakeLists.txt.
 *
 * Real deployments should:
 *   - scatter these checks across many call sites (not one function)
 *   - react via ars_react(), NOT an immediate exit
 *   - compare ars_self_file_hash() / ars_text_hash() against values baked in
 *     at release time (on-disk detects a patched file; in-memory detects a
 *     runtime patch that leaves the file intact)
 */
#include "shield.h"
#include <stdio.h>

int main(void) {
    unsigned flags = ars_scan();
    printf("debugger      : %s\n", (flags & ARS_FLAG_DEBUGGER) ? "DETECTED" : "clean");
    printf("frida         : %s\n", (flags & ARS_FLAG_FRIDA)    ? "DETECTED" : "clean");
    printf("inline hooks  : %s\n", (flags & ARS_FLAG_HOOK)     ? "DETECTED" : "clean");
    printf("timing anomaly: %s\n", (flags & ARS_FLAG_TIMING)   ? "DETECTED" : "clean");
    printf("env injection : %s\n", (flags & ARS_FLAG_ENVINJECT)? "DETECTED" : "clean");
    printf("self file hash: %016llx\n", (unsigned long long)ars_self_file_hash());
    printf("text seg hash : %016llx\n", (unsigned long long)ars_text_hash());

    unsigned long long demo = 0x1234;
    if (flags) demo = ars_react(demo); /* indirect reaction */
    printf("guarded value : %llx\n", demo);
    return 0;
}
