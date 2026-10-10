#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace demo {
constexpr size_t kKeyBytes = 32;
constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;
constexpr char kHkdfInfo[] =
    "ecc-secure-key-exchange/v1|ECDH-P256|HKDF-SHA256|AES-256-GCM";

using SessionKey = std::array<uint8_t, kKeyBytes>;
struct Packet {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, kNonceBytes> nonce{};
    std::array<uint8_t, kTagBytes> tag{};
};
SessionKey derive_session_key(const uint8_t* shared_secret, size_t secret_length);
Packet encrypt_message(const std::string& plaintext, const SessionKey& key);
std::string decrypt_message(const Packet& packet, const SessionKey& key);
}  // namespace demo
