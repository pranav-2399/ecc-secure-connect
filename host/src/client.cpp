#include "aead.hpp"
#include "atm.hpp"
#include "ecc.hpp"
#include "transport.hpp"

#include <openssl/crypto.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <algorithm>
#include <charconv>
#include <thread>

namespace {
	std::string to_hex(const uint8_t* bytes, size_t length) {
		static constexpr char digits[] = "0123456789abcdef";
		std::string result(length * 2, '0');
		for (size_t i = 0; i < length; ++i) {
			result[i * 2] = digits[bytes[i] >> 4];
			result[i * 2 + 1] = digits[bytes[i] & 0x0f];
		}
		return result;
	}

	void usage(const char* executable) {
		std::cerr << "Usage: " << executable << " <client-id> <peer-id> [relay-url] [--atm]\n"
				  << "       " << executable << " --unlock-account\n"
				  << "Example: " << executable << " Laptop ESP32 http://127.0.0.1:5000 --atm\n";
	}

	std::string env_or(const char* name, const char* fallback) {
		const char* value = std::getenv(name);
		return value && *value ? value : fallback;
	}

	bool is_pin(const std::string& value) {
		return value.size() >= 4 && value.size() <= 8 &&
			std::all_of(value.begin(), value.end(), [](unsigned char ch) {
				return ch >= '0' && ch <= '9';
			});
	}
	
	std::vector<uint8_t> decode_hex(const std::string& hex) {
		if (hex.size() % 2 != 0) throw std::runtime_error("Peer key is malformed hex");

		auto nibble = [](char ch) -> int {
			if (ch >= '0' && ch <= '9') return ch - '0';
			if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
			if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
			return -1;
		};
		std::vector<uint8_t> bytes(hex.size() / 2);
		for (size_t i = 0; i < bytes.size(); ++i) {
			const int high = nibble(hex[i * 2]), low = nibble(hex[i * 2 + 1]);
			if (high < 0 || low < 0) throw std::runtime_error("Peer key contains non-hex characters");
			bytes[i] = static_cast<uint8_t>((high << 4) | low);
		}
		return bytes;
	}
}

int main(int argc, char** argv) {
	if (argc == 2 && std::string(argv[1]) == "--unlock-account") {
		try {
			demo::unlock_account(env_or("ECC_ATM_ACCOUNT", "DEMO-001"));
			std::cout << "Demo account unlocked; failed-attempt counter reset.\n";
			return 0;
		} catch (const std::exception& error) {
			std::cerr << "Could not unlock demo account: " << error.what() << "\n";
			return 1;
		}
	}
	if (argc < 3 || argc > 5) { usage(argv[0]); return 2; }

	const std::string client_id = argv[1];
	const std::string peer_id = argv[2];
	std::string relay_url = "http://127.0.0.1:5000";
	bool atm_mode = false;
	bool relay_url_seen = false;
	for (int i = 3; i < argc; ++i) {
		if (std::string(argv[i]) == "--atm") atm_mode = true;
		else if (!relay_url_seen) {
			relay_url = argv[i];
			relay_url_seen = true;
		}
		else { usage(argv[0]); return 2; }
	}
	if (client_id == peer_id) { std::cerr << "Client and peer IDs must differ.\n"; return 2; }
	const char* configured_pin = std::getenv("ECC_ATM_PIN");
	std::string expected_pin = configured_pin == nullptr ? "" : configured_pin;
	if (atm_mode && !is_pin(expected_pin)) {
		std::cerr << "ATM mode requires ECC_ATM_PIN to be set to 4-8 digits.\n";
		return 2;
	}

	try {
		demo::CommunicationTransport transport(relay_url);
		demo::KeyPair key_pair = demo::generate_key_pair();
		const auto public_wire = demo::encode_public_key(key_pair.public_point);
		if (!transport.register_public_key(client_id, to_hex(public_wire.data(), public_wire.size())))
			throw std::runtime_error("Could not register public key");

		std::cout << "Registered public key for " << client_id << ". Waiting for " << peer_id << "...\n";
		std::optional<std::string> peer_key_hex;
		for (int attempt = 0; attempt < 120 && !peer_key_hex; ++attempt) {
			peer_key_hex = transport.get_public_key(peer_id);
			if (!peer_key_hex) std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
		if (!peer_key_hex) throw std::runtime_error("Peer did not register within 60 seconds");
		if (peer_key_hex->size() != demo::kPointBytes * 2)
			throw std::runtime_error("Peer public key has an invalid encoded length");

		const std::vector<uint8_t> peer_bytes = decode_hex(*peer_key_hex);
		const demo::Point peer_public = demo::decode_public_key(peer_bytes.data(), peer_bytes.size());
		auto shared_secret = demo::derive_shared_secret(key_pair.private_scalar, peer_public);
		demo::SessionKey session_key = demo::derive_session_key(shared_secret.data(), shared_secret.size());
		std::cout << "ECDH and HKDF session established with " << peer_id << ".\n";
		if (atm_mode)
			std::cout << "ATM verifier ready. Enter the PIN on the ESP32 serial terminal; use /quit here to close.\n";
		else
			std::cout << "Type a message and press Enter. Use /quit to end.\n";

		std::atomic<bool> running{true};
		std::mutex output_lock;
		std::thread receiver([&] {
			while (running.load()) {
				try {
					for (const auto& incoming : transport.receive_packets(client_id)) {
						std::lock_guard<std::mutex> guard(output_lock);
						if (incoming.sender_id != peer_id) {
							std::cout << "[rejected] Unexpected sender " << incoming.sender_id << "\n";
							continue;
						}
						try {
							std::string plaintext = demo::decrypt_message(incoming.packet, session_key);
							if (atm_mode && plaintext.rfind("ATM_WITHDRAW:", 0) == 0) {
								std::string fields = plaintext.substr(13);
								const size_t separator = fields.find(':');
								std::string supplied_pin = fields.substr(0, separator);
								int64_t amount = -1;
								if (separator != std::string::npos) {
									const std::string amount_text = fields.substr(separator + 1);
									const auto parsed = std::from_chars(amount_text.data(),
										amount_text.data() + amount_text.size(), amount);
									if (parsed.ec != std::errc{} || parsed.ptr != amount_text.data() + amount_text.size())
										amount = -1;
								}
								auto result = demo::process_withdrawal(env_or("ECC_ATM_ACCOUNT", "DEMO-001"),
										expected_pin, supplied_pin, amount);
								if (!supplied_pin.empty()) OPENSSL_cleanse(supplied_pin.data(), supplied_pin.size());
								if (!fields.empty()) OPENSSL_cleanse(fields.data(), fields.size());
								std::string response_text;
								switch (result.status) {
								case demo::WithdrawalStatus::approved:
									response_text = "ATM_RESULT:APPROVED:" + std::to_string(result.balance); break;
								case demo::WithdrawalStatus::invalid_pin:
									response_text = "ATM_RESULT:PIN_INVALID:" + std::to_string(result.attempts_remaining); break;
								case demo::WithdrawalStatus::locked:
									response_text = "ATM_RESULT:LOCKED"; break;
								case demo::WithdrawalStatus::insufficient_funds:
									response_text = "ATM_RESULT:INSUFFICIENT_FUNDS:" + std::to_string(result.balance); break;
								case demo::WithdrawalStatus::invalid_amount:
									response_text = "ATM_RESULT:INVALID_AMOUNT"; break;
								}
								OPENSSL_cleanse(plaintext.data(), plaintext.size());
								const demo::Packet response = demo::encrypt_message(response_text, session_key);
								transport.send_packet(client_id, peer_id, response);
								if (result.status == demo::WithdrawalStatus::approved)
									std::cout << "\n[ATM] Withdrawal approved; remaining demo balance: " << result.balance << ".\n> " << std::flush;
								else if (result.status == demo::WithdrawalStatus::invalid_pin)
									std::cout << "\n[ATM] PIN rejected; " << result.attempts_remaining << " attempt(s) remain.\n> " << std::flush;
								else if (result.status == demo::WithdrawalStatus::locked)
									std::cout << "\n[ATM] Account locked after three incorrect PIN attempts. Contact the operator.\n> " << std::flush;
								else if (result.status == demo::WithdrawalStatus::insufficient_funds)
									std::cout << "\n[ATM] Insufficient demo balance: " << result.balance << ".\n> " << std::flush;
								else
									std::cout << "\n[ATM] Invalid amount. Use 100-10000 in steps of 100.\n> " << std::flush;
							} else if (atm_mode) {
								OPENSSL_cleanse(plaintext.data(), plaintext.size());
								std::cout << "\n[ATM] Ignored an unexpected message.\n> " << std::flush;
							} else {
								std::cout << "\n" << incoming.sender_id << ": " << plaintext << "\n> " << std::flush;
							}
						} catch (const std::exception& error) {
							std::cout << "\n[rejected] Message authentication failed: " << error.what() << "\n> " << std::flush;
						}
					}
				} catch (const std::exception& error) {
					std::lock_guard<std::mutex> guard(output_lock);
					std::cerr << "[relay] " << error.what() << "\n";
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(350));
			}
		});

		std::string message;
		if (!atm_mode) std::cout << "> " << std::flush;
		while (std::getline(std::cin, message)) {
			if (message == "/quit") break;
			if (atm_mode) continue;
			if (message.empty()) { std::cout << "> " << std::flush; continue; }
			try {
				const demo::Packet packet = demo::encrypt_message(message, session_key);
				transport.send_packet(client_id, peer_id, packet);
			} catch (const std::exception& error) {
				std::cerr << "Send failed: " << error.what() << "\n";
			}
			std::cout << "> " << std::flush;
		}
		running = false;
		receiver.join();
		OPENSSL_cleanse(session_key.data(), session_key.size());
		OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
		if (!expected_pin.empty()) OPENSSL_cleanse(expected_pin.data(), expected_pin.size());
		key_pair.private_scalar = 0;
		std::cout << "Session ended.\n";
		return 0;
	} catch (const std::exception& error) {
		std::cerr << "Client failed: " << error.what() << "\n";
		return 1;
	}
}
