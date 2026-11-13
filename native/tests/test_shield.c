/* SPDX-License-Identifier: MIT
 * Minimal assertion harness for the native library. Run via `ctest`. */
#include "shield.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("ok   - %s\n", msg); } \
    else      { printf("FAIL - %s\n", msg); ++failures; } \
} while (0)

int main(void) {
    /* integrity hashes are non-zero and deterministic within a run */
    uint64_t f1 = ars_self_file_hash();
    uint64_t f2 = ars_self_file_hash();
    CHECK(f1 != 0,  "self_file_hash is non-zero");
    CHECK(f1 == f2, "self_file_hash is deterministic");

#if defined(__linux__)
    uint64_t t1 = ars_text_hash();
    uint64_t t2 = ars_text_hash();
    CHECK(t1 != 0,  "text_hash is non-zero on Linux");
    CHECK(t1 == t2, "text_hash is deterministic");
#endif

    /* env-injection detector flips with LD_PRELOAD */
    unsetenv("LD_PRELOAD");
    CHECK(ars_env_suspicious() == false, "env clean when no inject var set");
    setenv("LD_PRELOAD", "/tmp/evil.so", 1);
    CHECK(ars_env_suspicious() == true,  "env detected with LD_PRELOAD set");
    unsetenv("LD_PRELOAD");

    /* reaction perturbs its input and does not return it unchanged */
    uint64_t v = 0x1234;
    CHECK(ars_react(v) != v, "react perturbs the guarded value");

    /* scan returns a bitmask; under a normal test run (no debugger/frida/hook)
     * those three flags should be clear. timing is load-sensitive, so skip it. */
    unsigned flags = ars_scan();
    CHECK((flags & ARS_FLAG_FRIDA) == 0, "no frida in test run");
    CHECK((flags & ARS_FLAG_HOOK)  == 0, "no inline hook in test run");

    if (failures) { printf("\n%d check(s) failed\n", failures); return 1; }
    printf("\nall checks passed\n");
    return 0;
}
