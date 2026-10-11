#pragma once

#include "aead.hpp"
#include <optional>
#include <string>
#include <vector>

namespace demo {
struct IncomingMessage {
    std::string sender_id;
    Packet packet;
};

// Replace this HTTP adapter with a serial adapter when the ESP32 link is ready.
class CommunicationTransport {
public:
    explicit CommunicationTransport(std::string base_url);
    bool register_public_key(const std::string& client_id, const std::string& public_key_hex) const;
    std::optional<std::string> get_public_key(const std::string& peer_id) const;
    void send_packet(const std::string& sender_id, const std::string& recipient_id,
                     const Packet& packet) const;
    std::vector<IncomingMessage> receive_packets(const std::string& client_id) const;

private:
    std::string base_url_;
};
}  // namespace demo
