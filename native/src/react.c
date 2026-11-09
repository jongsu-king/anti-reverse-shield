/* SPDX-License-Identifier: MIT
 * Indirect reaction: never exit() at the detection site (that pinpoints it).
 * Delay, then perturb a value the caller's logic depends on, so the failure
 * manifests far away and looks like a bug rather than a tripped check. */
#include "shield.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

uint64_t ars_react(uint64_t value) {
    unsigned ms = 50u + (unsigned)(value & 0x3F);  /* 50-113 ms jitter */
#ifdef _WIN32
    Sleep(ms);  /* MSVC has no nanosleep */
#else
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = (long)ms * 1000000L;
    nanosleep(&ts, NULL);
#endif
    return value ^ 0xA5A5A5A5ULL; /* subtle corruption, surfaces downstream */
}
