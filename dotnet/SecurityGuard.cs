// SPDX-License-Identifier: MIT
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Shield
{
    /// <summary>
    /// Runtime anti-debug for .NET. IL is trivially decompiled (dnSpy/ILSpy),
    /// so pair this with ConfuserEx (anti tamper + constants) and, for anything
    /// that truly matters, a native DLL via P/Invoke or server-side logic.
    /// </summary>
    public static class SecurityGuard
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);

        public static bool IsDebugged()
        {
            if (Debugger.IsAttached || Debugger.IsLogging())
                return true;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                bool remote = false;
                try
                {
                    CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote);
                }
                catch (DllNotFoundException) { /* non-Windows */ }
                if (remote) return true;
            }
            return false;
        }
    }
}
