/* SPDX-License-Identifier: MIT
 * Detect library-injection via the dynamic loader's environment hooks.
 * LD_PRELOAD / LD_AUDIT (glibc) and DYLD_INSERT_LIBRARIES (macOS) are the
 * classic ways to inject a .so/.dylib that hooks the process before main(). */
#include "shield.h"
#include <stdlib.h>

bool ars_env_suspicious(void) {
    static const char *vars[] = {
        "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH_FORCE",
        "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"
    };
    for (unsigned i = 0; i < sizeof vars / sizeof *vars; ++i) {
        const char *v = getenv(vars[i]);
        if (v && v[0] != '\0') return true;
    }
    return false;
}
