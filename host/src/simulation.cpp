#include "aead.hpp"
#include "ecc.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        std::cout << "Laptop C++ simulation: Alice and Bob\n";
        const demo::Point g = demo::generator_point();
        const demo::Point two_g = demo::multiply_point(2, g);
        if (demo::multiply_point(1, g).x != g.x ||
            two_g.x != demo::BigInt("0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978") ||
            two_g.y != demo::BigInt("0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"))
            throw std::runtime_error("P-256 generator test vector failed");
        std::cout << "P-256 point arithmetic test vectors passed (1G and 2G).\n";
        const demo::KeyPair alice = demo::generate_key_pair();
        const demo::KeyPair bob = demo::generate_key_pair();
        const auto alice_public_wire = demo::encode_public_key(alice.public_point);
        const auto bob_public_wire = demo::encode_public_key(bob.public_point);
        const auto alice_received_bob = demo::decode_public_key(bob_public_wire.data(), bob_public_wire.size());
        const auto bob_received_alice = demo::decode_public_key(alice_public_wire.data(), alice_public_wire.size());
        std::cout << "Alice and Bob generated independent private scalars and public points.\n";
        std::cout << "Simulated relay exchanged public points only (" << alice_public_wire.size() << " bytes each).\n";

        const auto alice_secret = demo::derive_shared_secret(alice.private_scalar, alice_received_bob);
        const auto bob_secret = demo::derive_shared_secret(bob.private_scalar, bob_received_alice);
        if (alice_secret != bob_secret) throw std::runtime_error("ECDH mismatch");
        const auto alice_key = demo::derive_session_key(alice_secret.data(), alice_secret.size());
        const auto bob_key = demo::derive_session_key(bob_secret.data(), bob_secret.size());
        if (alice_key != bob_key) throw std::runtime_error("HKDF key mismatch");
        std::cout << "Both sides derived the same ECDH secret and HKDF-SHA256 AES key.\n";

        const std::string message = "Hello from the C++ ECC simulation";
        auto packet = demo::encrypt_message(message, alice_key);
        const std::string recovered = demo::decrypt_message(packet, bob_key);
        if (recovered != message) throw std::runtime_error("Message round trip failed");
        std::cout << "Alice encrypted a message with AES-256-GCM; Bob authenticated and decrypted it.\n";

        packet.tag[0] ^= 0x01;
        bool tampering_rejected = false;
        try { (void)demo::decrypt_message(packet, bob_key); }
        catch (const std::runtime_error&) { tampering_rejected = true; }
        if (!tampering_rejected) throw std::runtime_error("Tampered packet was accepted");
        std::cout << "Tampering check passed: modified authentication tag was rejected.\n";
        std::cout << "Simulation passed. This models the crypto exchange; it does not open a network socket.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Simulation failed: " << error.what() << '\n';
        return 1;
    }
}
