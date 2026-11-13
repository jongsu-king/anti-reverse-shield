/* feature test macro must precede all includes */
#if defined(__linux__)
#  define _POSIX_C_SOURCE 200112L
#endif
/* SPDX-License-Identifier: MIT */
#include "shield.h"
#include <stdio.h>
#include <stdint.h>

#if defined(_WIN32)
  #include <windows.h>
#elif defined(__APPLE__)
  #include <mach-o/dyld.h>
#else
  #include <unistd.h>
  #include <sys/types.h>
#endif

static const char *exe_path(char *buf, unsigned long cap) {
#if defined(_WIN32)
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
    if (n == 0 || n >= cap) return NULL;
    return buf;
#elif defined(__APPLE__)
    uint32_t sz = (uint32_t)cap;
    if (_NSGetExecutablePath(buf, &sz) != 0) return NULL;
    return buf;
#else
    ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    return buf;
#endif
}

uint64_t ars_self_file_hash(void) {
    char path[4096];
    if (!exe_path(path, sizeof path)) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint64_t h = 1469598103934665603ULL;      /* FNV-1a 64-bit offset */
    const uint64_t prime = 1099511628211ULL;
    unsigned char chunk[8192];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        for (size_t i = 0; i < got; ++i) {
            h ^= chunk[i];
            h *= prime;
        }
    }
    fclose(f);
    return h;
}

unsigned ars_scan(void) {
    unsigned flags = 0;
    if (ars_is_debugged())    flags |= ARS_FLAG_DEBUGGER;
    if (ars_frida_present())  flags |= ARS_FLAG_FRIDA;
    if (ars_hooks_present())  flags |= ARS_FLAG_HOOK;
    if (ars_timing_anomaly()) flags |= ARS_FLAG_TIMING;
    if (ars_env_suspicious()) flags |= ARS_FLAG_ENVINJECT;
    return flags;
}
