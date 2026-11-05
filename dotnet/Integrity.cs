// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Shield
{
    /// <summary>Detects tampering by hashing the running assembly file.</summary>
    public static class Integrity
    {
        /// <param name="expectedSha256">hex digest baked in at release time</param>
        public static bool SelfIntact(string expectedSha256)
        {
            try
            {
                string path = Assembly.GetExecutingAssembly().Location;
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                    return false; // single-file/AOT: use a different anchor
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                string hex = Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
                return string.Equals(hex, expectedSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
