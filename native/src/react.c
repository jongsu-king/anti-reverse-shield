/* SPDX-License-Identifier: MIT
 * Indirect reaction: never exit() at the detection site (that pinpoints it).
 * Delay, then perturb a value the caller's logic depends on, so the failure
 * manifests far away and looks like a bug rather than a tripped check. */
#include "shield.h"
#include <time.h>

uint64_t ars_react(uint64_t value) {
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = (long)(50 + (value & 0x3F)) * 1000000L; /* 50-113 ms jitter */
    nanosleep(&ts, NULL);
    return value ^ 0xA5A5A5A5ULL; /* subtle corruption, surfaces downstream */
}
