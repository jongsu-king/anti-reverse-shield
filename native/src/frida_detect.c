/* SPDX-License-Identifier: MIT */
#include "shield.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__) || defined(__ANDROID__)
/* Scan /proc/net/tcp[6] for a socket LISTENing on Frida's default ports
 * 27042 (0x699A) / 27043 (0x699B). State 0A == TCP_LISTEN. */
static bool scan_ports(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[512];
    bool hit = false;
    if (fgets(line, sizeof line, f)) { /* skip header */ }
    while (fgets(line, sizeof line, f)) {
        char local[128], st[8];
        if (sscanf(line, "%*s %127s %*s %7s", local, st) == 2) {
            char *colon = strrchr(local, ':');
            if (colon) {
                unsigned port = (unsigned)strtoul(colon + 1, NULL, 16);
                if ((port == 0x699A || port == 0x699B) && strcmp(st, "0A") == 0) {
                    hit = true;
                    break;
                }
            }
        }
    }
    fclose(f);
    return hit;
}
#endif

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
    if (scan_ports("/proc/net/tcp"))  return true;
    if (scan_ports("/proc/net/tcp6")) return true;
#endif
    return false;
}
