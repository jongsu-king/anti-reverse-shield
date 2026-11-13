/* SPDX-License-Identifier: MIT
 * Detect inline hooks by inspecting the prologue bytes of hot libc functions.
 * A detour overwrites the first instructions with a branch to the attacker's
 * code; the common encodings are recognizable even when the agent hides from
 * /proc/self/maps. Heuristic: one signal among several, never a sole gate. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE  /* glibc declares RTLD_DEFAULT in <dlfcn.h> only with this */
#endif
#include "shield.h"

#if (defined(__linux__) || defined(__APPLE__)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__))
#include <dlfcn.h>
#include <string.h>

#if defined(__aarch64__)
static bool prologue_hooked(const unsigned char *p) {
    if (!p) return false;
    uint32_t w0, w1;
    memcpy(&w0, p, 4);
    memcpy(&w1, p + 4, 4);
    /* LDR X16,#8 (0x58000050) ; BR X16 (0xD61F0200) : literal-pool absolute jump */
    if (w0 == 0x58000050u && w1 == 0xD61F0200u) return true;
    /* unconditional B imm26: top 6 bits == 0b000101 (0x14000000) */
    if ((w0 & 0xFC000000u) == 0x14000000u) return true;
    /* BR Xn (0xD61F0000 | Rn<<5) */
    if ((w0 & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    return false;
}
#else /* x86-64 */
static bool prologue_hooked(const unsigned char *p) {
    if (!p) return false;
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA)
        p += 4;                                         /* skip CET endbr64    */
    if (p[0] == 0xE9) return true;                      /* jmp rel32           */
    if (p[0] == 0xFF && (p[1] == 0x25 ||                /* jmp [rip+disp32]    */
                         p[1] == 0xE0 || p[1] == 0xE1)) /* jmp rax / jmp rcx   */
        return true;
    if (p[0] == 0x68 && p[5] == 0xC3) return true;      /* push imm32 ; ret    */
    if (p[0] == 0x48 && p[1] == 0xB8 &&                 /* mov rax, imm64 ;    */
        p[10] == 0xFF && p[11] == 0xE0) return true;    /*  ... jmp rax        */
    return false;
}
#endif

bool ars_hooks_present(void) {
    static const char *names[] = {
        "open", "read", "fopen", "connect", "ptrace", "dlopen", "recv", "send"
    };
    for (unsigned i = 0; i < sizeof names / sizeof *names; ++i) {
        const unsigned char *fn = (const unsigned char *)dlsym(RTLD_DEFAULT, names[i]);
        if (prologue_hooked(fn)) return true;
    }
    return false;
}

#else /* unsupported arch/OS */
bool ars_hooks_present(void) { return false; }
#endif
