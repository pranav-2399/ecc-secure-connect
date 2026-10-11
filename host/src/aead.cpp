#include "aead.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace demo {
	namespace {
		using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

		std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_length, const uint8_t* data, size_t data_length) {
			std::array<uint8_t, 32> result{};
			unsigned int result_length = 0;

			if (HMAC(EVP_sha256(), key, static_cast<int>(key_length), data, data_length, result.data(), &result_length) == nullptr || result_length != result.size())
				throw std::runtime_error("HMAC-SHA256 failed");
			return result;
		}
	}  // namespace

	SessionKey derive_session_key(const uint8_t* shared_secret, size_t secret_length) {
		if (shared_secret == nullptr || secret_length == 0) throw std::runtime_error("Missing ECDH secret");

		// RFC 5869 extract with absent salt represented by HashLen zero bytes.
		std::array<uint8_t, 32> zero_salt{};
		auto pseudorandom_key = hmac_sha256(zero_salt.data(), zero_salt.size(), shared_secret, secret_length);
		constexpr size_t info_length = sizeof(kHkdfInfo) - 1;
		std::array<uint8_t, info_length + 1> expand_input{};
		std::copy(kHkdfInfo, kHkdfInfo + info_length, expand_input.begin());
		expand_input[info_length] = 0x01;

		return hmac_sha256(pseudorandom_key.data(), pseudorandom_key.size(), expand_input.data(), expand_input.size());
	}

	Packet encrypt_message(const std::string& plaintext, const SessionKey& key) {
		Packet packet;
		if (RAND_bytes(packet.nonce.data(), packet.nonce.size()) != 1)
			throw std::runtime_error("OpenSSL nonce generation failed");

		CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		if (!context) throw std::runtime_error("Could not allocate AES-GCM context");

		int length = 0;
		packet.ciphertext.resize(plaintext.size() + 16);
		if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
			EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, packet.nonce.size(), nullptr) != 1 ||
			EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), packet.nonce.data()) != 1 ||
			EVP_EncryptUpdate(context.get(), packet.ciphertext.data(), &length,
							reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()) != 1)
			throw std::runtime_error("AES-256-GCM encryption failed");

		int total = length;
		if (EVP_EncryptFinal_ex(context.get(), packet.ciphertext.data() + total, &length) != 1)
			throw std::runtime_error("AES-256-GCM finalization failed");

		total += length;
		packet.ciphertext.resize(total);
		if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, packet.tag.size(), packet.tag.data()) != 1)
			throw std::runtime_error("AES-GCM tag retrieval failed");
			
		return packet;
	}

	std::string decrypt_message(const Packet& packet, const SessionKey& key) {
		CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		if (!context) throw std::runtime_error("Could not allocate AES-GCM context");

		std::vector<uint8_t> plaintext(packet.ciphertext.size() + 16);
		int length = 0;
		if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
			EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, packet.nonce.size(), nullptr) != 1 ||
			EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), packet.nonce.data()) != 1 ||
			EVP_DecryptUpdate(context.get(), plaintext.data(), &length,
							packet.ciphertext.data(), packet.ciphertext.size()) != 1)
			throw std::runtime_error("AES-256-GCM decryption failed");

		int total = length;
		if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
								packet.tag.size(), const_cast<uint8_t*>(packet.tag.data())) != 1 ||
			EVP_DecryptFinal_ex(context.get(), plaintext.data() + total, &length) != 1)
			throw std::runtime_error("AES-GCM authentication failed");

		total += length;
		return std::string(plaintext.begin(), plaintext.begin() + total);
	}
}  // namespace demo
