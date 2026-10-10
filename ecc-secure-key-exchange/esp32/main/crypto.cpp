#include "crypto.hpp"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

namespace ecc_demo {
namespace {
constexpr char kP[] = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
constexpr char kA[] = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
constexpr char kGx[] = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
constexpr char kGy[] = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
constexpr char kN[] = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

struct Mpi {
    mbedtls_mpi value;
    Mpi() { mbedtls_mpi_init(&value); }
    ~Mpi() { mbedtls_mpi_free(&value); }
    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;
};
struct AffinePoint { Mpi x; Mpi y; bool infinity = true; };

int read_hex(mbedtls_mpi* output, const char* value) {
    return mbedtls_mpi_read_string(output, 16, value);
}

// Affine short-Weierstrass point addition for y^2 = x^3 - 3x + b (mod p).
int point_add(const AffinePoint& lhs, const AffinePoint& rhs,
              const mbedtls_mpi& p, const mbedtls_mpi& a, AffinePoint& out) {
    if (lhs.infinity || rhs.infinity) {
        const AffinePoint& source = lhs.infinity ? rhs : lhs;
        out.infinity = source.infinity;
        if (out.infinity) return 0;
        int rc = mbedtls_mpi_copy(&out.x.value, &source.x.value);
        if (rc == 0) rc = mbedtls_mpi_copy(&out.y.value, &source.y.value);
        return rc;
    }
    const bool same_x = mbedtls_mpi_cmp_mpi(&lhs.x.value, &rhs.x.value) == 0;
    if (same_x && mbedtls_mpi_cmp_mpi(&lhs.y.value, &rhs.y.value) != 0) {
        out.infinity = true;  // P + (-P) = infinity.
        return 0;
    }

    Mpi numerator, denominator, inverse, slope, temp, x3, y3;
    int rc = 0;
    if (same_x) {
        if (mbedtls_mpi_cmp_int(&lhs.y.value, 0) == 0) {
            out.infinity = true;
            return 0;
        }
        // For doubling: slope = (3*x1^2 + a) / (2*y1) mod p.
        rc = mbedtls_mpi_mul_mpi(&temp.value, &lhs.x.value, &lhs.x.value);
        if (rc == 0) rc = mbedtls_mpi_mul_int(&temp.value, &temp.value, 3);
        if (rc == 0) rc = mbedtls_mpi_add_mpi(&temp.value, &temp.value, &a);
        if (rc == 0) rc = mbedtls_mpi_mod_mpi(&numerator.value, &temp.value, &p);
        if (rc == 0) rc = mbedtls_mpi_mul_int(&temp.value, &lhs.y.value, 2);
        if (rc == 0) rc = mbedtls_mpi_mod_mpi(&denominator.value, &temp.value, &p);
    } else {
        // For addition: slope = (y2-y1) / (x2-x1) mod p.
        rc = mbedtls_mpi_sub_mpi(&temp.value, &rhs.y.value, &lhs.y.value);
        if (rc == 0) rc = mbedtls_mpi_mod_mpi(&numerator.value, &temp.value, &p);
        if (rc == 0) rc = mbedtls_mpi_sub_mpi(&temp.value, &rhs.x.value, &lhs.x.value);
        if (rc == 0) rc = mbedtls_mpi_mod_mpi(&denominator.value, &temp.value, &p);
    }
    if (rc == 0) rc = mbedtls_mpi_inv_mod(&inverse.value, &denominator.value, &p);
    if (rc == 0) rc = mbedtls_mpi_mul_mpi(&temp.value, &numerator.value, &inverse.value);
    if (rc == 0) rc = mbedtls_mpi_mod_mpi(&slope.value, &temp.value, &p);
    // x3 = slope^2-x1-x2; y3 = slope*(x1-x3)-y1 (mod p).
    if (rc == 0) rc = mbedtls_mpi_mul_mpi(&temp.value, &slope.value, &slope.value);
    if (rc == 0) rc = mbedtls_mpi_sub_mpi(&temp.value, &temp.value, &lhs.x.value);
    if (rc == 0) rc = mbedtls_mpi_sub_mpi(&temp.value, &temp.value, &rhs.x.value);
    if (rc == 0) rc = mbedtls_mpi_mod_mpi(&x3.value, &temp.value, &p);
    if (rc == 0) rc = mbedtls_mpi_sub_mpi(&temp.value, &lhs.x.value, &x3.value);
    if (rc == 0) rc = mbedtls_mpi_mul_mpi(&temp.value, &slope.value, &temp.value);
    if (rc == 0) rc = mbedtls_mpi_sub_mpi(&temp.value, &temp.value, &lhs.y.value);
    if (rc == 0) rc = mbedtls_mpi_mod_mpi(&y3.value, &temp.value, &p);
    if (rc == 0) rc = mbedtls_mpi_copy(&out.x.value, &x3.value);
    if (rc == 0) rc = mbedtls_mpi_copy(&out.y.value, &y3.value);
    if (rc == 0) out.infinity = false;
    return rc;
}

// Double-and-add scalar multiplication: result = scalar * generator.
int scalar_multiply(const mbedtls_mpi& scalar, const AffinePoint& generator,
                    const mbedtls_mpi& p, const mbedtls_mpi& a, AffinePoint& out) {
    AffinePoint result, addend;
    int rc = mbedtls_mpi_copy(&addend.x.value, &generator.x.value);
    if (rc == 0) rc = mbedtls_mpi_copy(&addend.y.value, &generator.y.value);
    addend.infinity = false;
    const size_t bits = mbedtls_mpi_bitlen(&scalar);
    for (size_t bit = 0; rc == 0 && bit < bits; ++bit) {
        if (mbedtls_mpi_get_bit(&scalar, bit)) {
            AffinePoint sum;
            rc = point_add(result, addend, p, a, sum);
            if (rc == 0) {
                result.infinity = sum.infinity;
                if (!sum.infinity) {
                    rc = mbedtls_mpi_copy(&result.x.value, &sum.x.value);
                    if (rc == 0) rc = mbedtls_mpi_copy(&result.y.value, &sum.y.value);
                }
            }
        }
        if (rc == 0 && bit + 1 < bits) {
            AffinePoint doubled;
            rc = point_add(addend, addend, p, a, doubled);
            if (rc == 0) {
                addend.infinity = doubled.infinity;
                if (!doubled.infinity) {
                    rc = mbedtls_mpi_copy(&addend.x.value, &doubled.x.value);
                    if (rc == 0) rc = mbedtls_mpi_copy(&addend.y.value, &doubled.y.value);
                }
            }
        }
    }
    if (rc == 0 && result.infinity) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (rc == 0) {
        out.infinity = false;
        rc = mbedtls_mpi_copy(&out.x.value, &result.x.value);
        if (rc == 0) rc = mbedtls_mpi_copy(&out.y.value, &result.y.value);
    }
    return rc;
}
}  // namespace

Rng::Rng() { mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&drbg); }
Rng::~Rng() { mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy); }
int Rng::seed() {
    static const unsigned char personalization[] = "ecc-secure-key-exchange-v1";
    return mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                  personalization, sizeof(personalization) - 1);
}
int Rng::random(void* context, unsigned char* output, size_t length) {
    return mbedtls_ctr_drbg_random(static_cast<mbedtls_ctr_drbg_context*>(context),
                                   output, length);
}

KeyPair::KeyPair() {
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&private_scalar);
    mbedtls_ecp_point_init(&public_point);
}
KeyPair::~KeyPair() {
    mbedtls_mpi_free(&private_scalar);
    mbedtls_ecp_point_free(&public_point);
    mbedtls_ecp_group_free(&group);
}

int generate_key_pair(Rng& rng, KeyPair& key) {
    int rc = mbedtls_ecp_group_load(&key.group, MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) return rc;
    Mpi p, a, n;
    if ((rc = read_hex(&p.value, kP)) != 0 || (rc = read_hex(&a.value, kA)) != 0 ||
        (rc = read_hex(&n.value, kN)) != 0) return rc;
    // Rejection sampling chooses the private scalar d uniformly in [1, n-1].
    std::array<unsigned char, 32> candidate{};
    do {
        rc = Rng::random(&rng.drbg, candidate.data(), candidate.size());
        if (rc != 0) {
            mbedtls_platform_zeroize(candidate.data(), candidate.size());
            return rc;
        }
        rc = mbedtls_mpi_read_binary(&key.private_scalar, candidate.data(), candidate.size());
        if (rc != 0) {
            mbedtls_platform_zeroize(candidate.data(), candidate.size());
            return rc;
        }
    } while (mbedtls_mpi_cmp_int(&key.private_scalar, 0) <= 0 ||
             mbedtls_mpi_cmp_mpi(&key.private_scalar, &n.value) >= 0);
    mbedtls_platform_zeroize(candidate.data(), candidate.size());

    AffinePoint generator, public_point;
    if ((rc = read_hex(&generator.x.value, kGx)) != 0 ||
        (rc = read_hex(&generator.y.value, kGy)) != 0) return rc;
    generator.infinity = false;
    rc = scalar_multiply(key.private_scalar, generator, p.value, a.value, public_point);
    if (rc == 0) rc = mbedtls_mpi_copy(&key.public_point.X, &public_point.x.value);
    if (rc == 0) rc = mbedtls_mpi_copy(&key.public_point.Y, &public_point.y.value);
    if (rc == 0) rc = mbedtls_mpi_lset(&key.public_point.Z, 1);
    if (rc == 0) rc = mbedtls_ecp_check_pubkey(&key.group, &key.public_point);
    return rc;
}

int encode_public_key(const KeyPair& key,
                      std::array<uint8_t, kPublicKeyBytes>& output) {
    size_t written = 0;
    int rc = mbedtls_ecp_point_write_binary(
        &key.group, &key.public_point, MBEDTLS_ECP_PF_UNCOMPRESSED, &written,
        output.data(), output.size());
    return rc != 0 ? rc : (written == output.size() ? 0 : MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
}

int decode_public_key(const uint8_t* input, size_t length,
                      mbedtls_ecp_group& group, mbedtls_ecp_point& point) {
    if (input == nullptr || length != kPublicKeyBytes || input[0] != 0x04)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    int rc = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) rc = mbedtls_ecp_point_read_binary(&group, &point, input, length);
    if (rc == 0) rc = mbedtls_ecp_check_pubkey(&group, &point);
    return rc;
}

int derive_shared_secret(Rng& rng, const KeyPair& local,
                         const mbedtls_ecp_group& peer_group,
                         const mbedtls_ecp_point& peer_public,
                         std::array<uint8_t, 32>& output) {
    mbedtls_mpi secret;
    mbedtls_mpi_init(&secret);
    int rc = mbedtls_ecdh_compute_shared(
        const_cast<mbedtls_ecp_group*>(&peer_group), &secret,
        const_cast<mbedtls_ecp_point*>(&peer_public),
        const_cast<mbedtls_mpi*>(&local.private_scalar), Rng::random, &rng.drbg);
    if (rc == 0) rc = mbedtls_mpi_write_binary(&secret, output.data(), output.size());
    mbedtls_mpi_free(&secret);
    return rc;
}

int derive_session_key(const uint8_t* shared_secret, size_t secret_length,
                       const uint8_t* salt, size_t salt_length,
                       std::array<uint8_t, kSessionKeyBytes>& output) {
    const mbedtls_md_info_t* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (sha256 == nullptr || shared_secret == nullptr) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    return mbedtls_hkdf(sha256, salt, salt_length, shared_secret, secret_length,
                        reinterpret_cast<const uint8_t*>(kHkdfInfo),
                        sizeof(kHkdfInfo) - 1, output.data(), output.size());
}

int encrypt_gcm(Rng& rng, const uint8_t* key, const uint8_t* plaintext,
                size_t plaintext_length, uint8_t* ciphertext,
                std::array<uint8_t, kNonceBytes>& nonce,
                std::array<uint8_t, kTagBytes>& tag) {
    if (key == nullptr || (plaintext_length && (plaintext == nullptr || ciphertext == nullptr)))
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    int rc = Rng::random(&rng.drbg, nonce.data(), nonce.size());
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (rc == 0) rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) rc = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT, plaintext_length, nonce.data(), nonce.size(),
        nullptr, 0, plaintext, ciphertext, tag.size(), tag.data());
    mbedtls_gcm_free(&gcm);
    return rc;
}

int decrypt_gcm(const uint8_t* key, const uint8_t* ciphertext,
                size_t ciphertext_length, const uint8_t* nonce,
                const uint8_t* tag, uint8_t* plaintext) {
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (ciphertext_length && (ciphertext == nullptr || plaintext == nullptr)))
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) rc = mbedtls_gcm_auth_decrypt(
        &gcm, ciphertext_length, nonce, kNonceBytes, nullptr, 0, tag, kTagBytes,
        ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return rc;
}
}  // namespace ecc_demo
