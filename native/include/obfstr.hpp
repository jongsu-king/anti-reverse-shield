// SPDX-License-Identifier: MIT
// Compile-time XOR string: the plaintext never appears in the binary,
// so `strings` and static decompilers do not see it. Decrypt only at the
// point of use, and overwrite the buffer immediately after.
#ifndef ARS_OBFSTR_HPP
#define ARS_OBFSTR_HPP
#include <array>
#include <cstddef>

namespace ars {

template <std::size_t N, char KEY>
class XorStr {
    std::array<char, N> enc_{};
public:
    constexpr explicit XorStr(const char (&s)[N]) {
        for (std::size_t i = 0; i < N; ++i)
            enc_[i] = static_cast<char>(s[i] ^ KEY);
    }
    // Writes the decrypted, NUL-terminated string into `out` (size >= N).
    char *decrypt(char *out) const {
        for (std::size_t i = 0; i < N; ++i)
            out[i] = static_cast<char>(enc_[i] ^ KEY);
        return out;
    }
    static constexpr std::size_t size() { return N; }
};

} // namespace ars

// Pick a per-string key at the call site for variety.
#define ARS_OBF(s)      (ars::XorStr<sizeof(s), 0x5A>(s))
#define ARS_OBF_K(s, k) (ars::XorStr<sizeof(s), (k)>(s))

#endif // ARS_OBFSTR_HPP
