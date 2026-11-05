/* SPDX-License-Identifier: MIT
 * Hash the in-memory executable segment of the main program. Unlike the
 * on-disk hash, this detects a RUNTIME patch (e.g. a debugger NOP-ing a check)
 * that leaves the file on disk untouched. Linux implementation walks the
 * program headers; other platforms return 0 (documented limitation). */
#if defined(__linux__)
#  define _GNU_SOURCE
#  include <link.h>
#  include "shield.h"

struct ctx { uint64_t h; };

static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    /* main executable is the entry whose name is empty */
    if (info->dlpi_name && info->dlpi_name[0] != '\0') return 0;
    struct ctx *c = (struct ctx *)data;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            const unsigned char *base =
                (const unsigned char *)(info->dlpi_addr + ph->p_vaddr);
            uint64_t h = 1469598103934665603ULL;
            for (ElfW(Word) k = 0; k < ph->p_memsz; ++k) {
                h ^= base[k];
                h *= 1099511628211ULL;
            }
            c->h = h;
        }
    }
    return 1; /* stop after the main object */
}

uint64_t ars_text_hash(void) {
    struct ctx c = { 0 };
    dl_iterate_phdr(cb, &c);
    return c.h;
}

#else
#  include "shield.h"
uint64_t ars_text_hash(void) { return 0; } /* TODO: Mach-O / PE segment walk */
#endif
