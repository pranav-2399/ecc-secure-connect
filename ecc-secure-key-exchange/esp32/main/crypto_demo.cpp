#include <array>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include "crypto.hpp"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"

extern "C" void app_main(void) {
    ecc_demo::Rng rng;
    ecc_demo::KeyPair alice;
    ecc_demo::KeyPair bob;
    int rc = rng.seed();
    if (rc == 0) rc = ecc_demo::generate_key_pair(rng, alice);
    if (rc == 0) rc = ecc_demo::generate_key_pair(rng, bob);
    std::array<uint8_t, ecc_demo::kPublicKeyBytes> alice_public{};
    std::array<uint8_t, ecc_demo::kPublicKeyBytes> bob_public{};
    if (rc == 0) rc = ecc_demo::encode_public_key(alice, alice_public);
    if (rc == 0) rc = ecc_demo::encode_public_key(bob, bob_public);
    if (rc != 0) {
        std::printf("ESP32 crypto setup failed: -0x%04x\n",
                    static_cast<unsigned>(-rc));
        return;
    }
    std::printf("Generated Alice and Bob P-256 keypairs with explicit scalar multiplication.\n");
    std::printf("Alice SEC1 public point: ");
    for (uint8_t byte : alice_public) std::printf("%02x", byte);
    std::printf("\nBob SEC1 public point:   ");
    for (uint8_t byte : bob_public) std::printf("%02x", byte);
    std::printf("\nPrivate scalars remain in device memory.\n");

    mbedtls_ecp_group peer_group_a, peer_group_b;
    mbedtls_ecp_point peer_point_a, peer_point_b;
    mbedtls_ecp_group_init(&peer_group_a);
    mbedtls_ecp_group_init(&peer_group_b);
    mbedtls_ecp_point_init(&peer_point_a);
    mbedtls_ecp_point_init(&peer_point_b);
    rc = ecc_demo::decode_public_key(bob_public.data(), bob_public.size(), peer_group_a, peer_point_a);
    if (rc == 0) rc = ecc_demo::decode_public_key(alice_public.data(), alice_public.size(), peer_group_b, peer_point_b);
    std::array<uint8_t, 32> secret_a{}, secret_b{};
    if (rc == 0) rc = ecc_demo::derive_shared_secret(rng, alice, peer_group_a, peer_point_a, secret_a);
    if (rc == 0) rc = ecc_demo::derive_shared_secret(rng, bob, peer_group_b, peer_point_b, secret_b);
    if (rc == 0 && secret_a != secret_b) rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    std::array<uint8_t, ecc_demo::kSessionKeyBytes> key_a{}, key_b{};
    if (rc == 0) rc = ecc_demo::derive_session_key(secret_a.data(), secret_a.size(), nullptr, 0, key_a);
    if (rc == 0) rc = ecc_demo::derive_session_key(secret_b.data(), secret_b.size(), nullptr, 0, key_b);
    constexpr char message[] = "ESP32 C++ crypto self-test";
    std::array<uint8_t, sizeof(message) - 1> ciphertext{}, recovered{};
    std::array<uint8_t, ecc_demo::kNonceBytes> nonce{};
    std::array<uint8_t, ecc_demo::kTagBytes> tag{};
    if (rc == 0) rc = ecc_demo::encrypt_gcm(
        rng, key_a.data(), reinterpret_cast<const uint8_t*>(message), sizeof(message) - 1,
        ciphertext.data(), nonce, tag);
    if (rc == 0) rc = ecc_demo::decrypt_gcm(
        key_b.data(), ciphertext.data(), ciphertext.size(), nonce.data(), tag.data(), recovered.data());
    if (rc == 0 && !std::equal(recovered.begin(), recovered.end(), message))
        rc = MBEDTLS_ERR_GCM_AUTH_FAILED;
    if (rc == 0) {
        tag[0] ^= 0x01;
        const int tamper_rc = ecc_demo::decrypt_gcm(
            key_b.data(), ciphertext.data(), ciphertext.size(), nonce.data(), tag.data(), recovered.data());
        if (tamper_rc == 0) rc = MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    mbedtls_ecp_point_free(&peer_point_a);
    mbedtls_ecp_point_free(&peer_point_b);
    mbedtls_ecp_group_free(&peer_group_a);
    mbedtls_ecp_group_free(&peer_group_b);
    mbedtls_platform_zeroize(secret_a.data(), secret_a.size());
    mbedtls_platform_zeroize(secret_b.data(), secret_b.size());
    mbedtls_platform_zeroize(key_a.data(), key_a.size());
    mbedtls_platform_zeroize(key_b.data(), key_b.size());
    if (rc != 0) {
        std::printf("ESP32 crypto self-test failed: -0x%04x\n", static_cast<unsigned>(-rc));
        return;
    }
    std::printf("Self-test passed: ECDH, HKDF-SHA256, AES-256-GCM round trip, and modified-tag rejection.\n");
}
