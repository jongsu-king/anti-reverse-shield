/* SPDX-License-Identifier: MIT
 * Minimal demo. Build with the provided CMakeLists.txt.
 *
 * Real deployments should:
 *   - scatter these checks across many call sites (not one function)
 *   - react with delay / data corruption, NOT an immediate exit
 *   - compare ars_self_file_hash() against a value baked in at release
 */
#include "shield.h"
#include <stdio.h>

int main(void) {
    unsigned flags = ars_scan();
    printf("debugger : %s\n", (flags & ARS_FLAG_DEBUGGER) ? "DETECTED" : "clean");
    printf("frida    : %s\n", (flags & ARS_FLAG_FRIDA)    ? "DETECTED" : "clean");
    printf("self hash: %016llx\n", (unsigned long long)ars_self_file_hash());
    return 0;
}
