/* SPDX-License-Identifier: MIT */
#include "shield.h"

#if defined(_WIN32)
  #include <windows.h>
  bool ars_is_debugged(void) {
      if (IsDebuggerPresent()) return true;
      BOOL remote = FALSE;
      CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
      if (remote) return true;
  #if defined(_MSC_VER)
    #if defined(_M_X64)
      const unsigned char *peb = (const unsigned char *)__readgsqword(0x60);
    #else
      const unsigned char *peb = (const unsigned char *)__readfsdword(0x30);
    #endif
      if (peb && peb[2] != 0) return true; /* PEB->BeingDebugged */
  #endif
      return false;
  }

#elif defined(__APPLE__)
  #include <sys/sysctl.h>
  #include <unistd.h>
  #include <string.h>
  bool ars_is_debugged(void) {
      struct kinfo_proc info;
      size_t size = sizeof(info);
      int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
      memset(&info, 0, sizeof(info));
      if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return false;
      return (info.kp_proc.p_flag & P_TRACED) != 0;
  }

#else /* Linux / generic */
  #include <sys/ptrace.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  bool ars_is_debugged(void) {
      /* TracerPid from /proc first (does not perturb state). */
      FILE *f = fopen("/proc/self/status", "r");
      if (f) {
          char line[256];
          while (fgets(line, sizeof line, f)) {
              if (strncmp(line, "TracerPid:", 10) == 0) {
                  int pid = atoi(line + 10);
                  fclose(f);
                  if (pid != 0) return true;
                  return false;
              }
          }
          fclose(f);
      }
      /* Fallback: self-trace probe. */
      if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return true;
      ptrace(PTRACE_DETACH, 0, 0, 0);
      return false;
  }
#endif
