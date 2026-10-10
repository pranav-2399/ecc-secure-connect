#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"

namespace ecc_demo {
constexpr size_t kPublicKeyBytes = 65;
constexpr size_t kSessionKeyBytes = 32;
constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;
constexpr char kHkdfInfo[] =
    "ecc-secure-key-exchange/v1|ECDH-P256|HKDF-SHA256|AES-256-GCM";

struct Rng {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    Rng();
    ~Rng();
    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;
    int seed();
    static int random(void* context, unsigned char* output, size_t length);
};

struct KeyPair {
    mbedtls_ecp_group group;
    mbedtls_mpi private_scalar;
    mbedtls_ecp_point public_point;
    KeyPair();
    ~KeyPair();
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
};

int generate_key_pair(Rng& rng, KeyPair& key);
int encode_public_key(const KeyPair& key, std::array<uint8_t, kPublicKeyBytes>& output);
int decode_public_key(const uint8_t* input, size_t length,
                      mbedtls_ecp_group& group, mbedtls_ecp_point& point);
int derive_shared_secret(Rng& rng, const KeyPair& local,
                         const mbedtls_ecp_group& peer_group,
                         const mbedtls_ecp_point& peer_public,
                         std::array<uint8_t, 32>& output);
int derive_session_key(const uint8_t* shared_secret, size_t secret_length,
                       const uint8_t* salt, size_t salt_length,
                       std::array<uint8_t, kSessionKeyBytes>& output);
int encrypt_gcm(Rng& rng, const uint8_t* key, const uint8_t* plaintext,
                size_t plaintext_length, uint8_t* ciphertext,
                std::array<uint8_t, kNonceBytes>& nonce,
                std::array<uint8_t, kTagBytes>& tag);
int decrypt_gcm(const uint8_t* key, const uint8_t* ciphertext,
                size_t ciphertext_length, const uint8_t* nonce,
                const uint8_t* tag, uint8_t* plaintext);
}  // namespace ecc_demo
