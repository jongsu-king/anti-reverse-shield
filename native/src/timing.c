/* SPDX-License-Identifier: MIT
 * A debugger that single-steps or breakpoints inflates the wall-clock time
 * between adjacent instructions by orders of magnitude. */
#include "shield.h"
#include <time.h>

bool ars_timing_anomaly(void) {
#if defined(CLOCK_MONOTONIC)
    struct timespec a, b;
    if (clock_gettime(CLOCK_MONOTONIC, &a) != 0) return false;
    volatile unsigned x = 0;
    for (int i = 0; i < 1000; ++i) x += (unsigned)i;
    if (clock_gettime(CLOCK_MONOTONIC, &b) != 0) return false;
    (void)x;
    long ns = (b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec);
    return ns > 2000000L; /* >2ms for ~1000 adds => someone is watching */
#else
    return false;
#endif
}
