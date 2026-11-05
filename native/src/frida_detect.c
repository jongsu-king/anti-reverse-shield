/* SPDX-License-Identifier: MIT */
#include "shield.h"
#include <string.h>
#include <stdio.h>

bool ars_frida_present(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            if (strstr(line, "frida")  || strstr(line, "gum-js") ||
                strstr(line, "gadget") || strstr(line, "linjector")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
#endif
    /* Cross-platform extension points (not implemented here to stay portable):
     *  - probe default Frida ports 27042/27043
     *  - look for named pipes / threads created by the agent
     *  - checksum libc PLT entries for inline hooks
     */
    return false;
}
