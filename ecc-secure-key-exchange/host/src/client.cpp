#include "aead.hpp"
#include "ecc.hpp"
#include "transport.hpp"

#include <openssl/crypto.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
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
    std::cerr << "Usage: " << executable << " <client-id> <peer-id> [relay-url]\n"
              << "Example: " << executable << " Alice Bob http://127.0.0.1:5000\n";
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
    if (argc < 3 || argc > 4) { usage(argv[0]); return 2; }
    const std::string client_id = argv[1];
    const std::string peer_id = argv[2];
    const std::string relay_url = argc == 4 ? argv[3] : "http://127.0.0.1:5000";
    if (client_id == peer_id) { std::cerr << "Client and peer IDs must differ.\n"; return 2; }

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
        std::cout << "ECDH and HKDF session established with " << peer_id << ".\n"
                  << "Type a message and press Enter. Use /quit to end.\n";

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
                            const std::string plaintext = demo::decrypt_message(incoming.packet, session_key);
                            std::cout << "\n" << incoming.sender_id << ": " << plaintext << "\n> " << std::flush;
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
        std::cout << "> " << std::flush;
        while (std::getline(std::cin, message)) {
            if (message == "/quit") break;
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
        key_pair.private_scalar = 0;
        std::cout << "Session ended.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Client failed: " << error.what() << "\n";
        return 1;
    }
}
