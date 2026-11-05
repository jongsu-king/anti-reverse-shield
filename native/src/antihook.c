/* SPDX-License-Identifier: MIT
 * Detect inline hooks by inspecting the prologue bytes of hot libc functions.
 * A detour overwrites the first bytes with a jump to the attacker's code; the
 * common encodings are recognizable even when the agent hides from maps. */
#include "shield.h"

#if defined(__linux__) || defined(__APPLE__)
#include <dlfcn.h>

static bool prologue_hooked(void *fn) {
    if (!fn) return false;
    const unsigned char *p = (const unsigned char *)fn;
    if (p[0] == 0xE9) return true;                       /* jmp rel32            */
    if (p[0] == 0xFF && (p[1] == 0x25 ||                 /* jmp [rip+disp32]     */
                         p[1] == 0xE0 || p[1] == 0xE1))  /* jmp rax / jmp rcx    */
        return true;
    if (p[0] == 0x68 && p[5] == 0xC3) return true;       /* push imm32 ; ret     */
    if (p[0] == 0x48 && p[1] == 0xB8 &&                  /* mov rax, imm64 ;     */
        p[10] == 0xFF && p[11] == 0xE0) return true;     /*  ... jmp rax         */
    return false;
}

bool ars_hooks_present(void) {
    static const char *names[] = {
        "open", "read", "fopen", "connect", "ptrace", "dlopen", "recv", "send"
    };
    for (unsigned i = 0; i < sizeof names / sizeof *names; ++i) {
        void *fn = dlsym(RTLD_DEFAULT, names[i]);
        if (prologue_hooked(fn)) return true;
    }
    return false;
}

#else /* Windows / other: prologue scan would use GetProcAddress on ntdll */
bool ars_hooks_present(void) { return false; }
#endif
