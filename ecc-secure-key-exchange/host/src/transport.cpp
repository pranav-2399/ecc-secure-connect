#include "transport.hpp"

#include <curl/curl.h>
#include <array>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace demo {
namespace {
std::once_flag curl_once;
void init_curl() {
    std::call_once(curl_once, [] {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
            throw std::runtime_error("libcurl initialization failed");
    });
}
size_t append_response(char* data, size_t size, size_t count, void* destination) {
    const size_t bytes = size * count;
    static_cast<std::string*>(destination)->append(data, bytes);
    return bytes;
}
struct HttpResponse { long status; std::string body; };
HttpResponse request(const std::string& method, const std::string& url, const std::string& body = {}) {
    init_curl();
    CURL* handle = curl_easy_init();
    if (!handle) throw std::runtime_error("Could not allocate HTTP request");
    HttpResponse response{};
    curl_slist* headers = nullptr;
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, append_response);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, 2500L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, 6000L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    if (method == "POST") {
        curl_easy_setopt(handle, CURLOPT_POST, 1L);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        headers = curl_slist_append(nullptr, "Content-Type: text/plain; charset=utf-8");
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    }
    CURLcode rc = curl_easy_perform(handle);
    if (rc == CURLE_OK) curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response.status);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(handle);
    if (rc != CURLE_OK) throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(rc));
    return response;
}
std::string to_hex(const uint8_t* bytes, size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output(length * 2, '0');
    for (size_t i = 0; i < length; ++i) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 0x0f];
    }
    return output;
}
std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("Malformed hex in relay packet");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> output(hex.size() / 2);
    for (size_t i = 0; i < output.size(); ++i) {
        const int hi = nibble(hex[i * 2]), lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("Malformed hex in relay packet");
        output[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return output;
}
std::string check_client_id(const std::string& id) {
    if (id.empty() || id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
        throw std::runtime_error("Client IDs may contain only letters, digits, underscore, and hyphen");
    return id;
}
}  // namespace

CommunicationTransport::CommunicationTransport(std::string base_url) : base_url_(std::move(base_url)) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

bool CommunicationTransport::register_public_key(const std::string& client_id,
                                                  const std::string& public_key_hex) const {
    const auto response = request("POST", base_url_ + "/register/" + check_client_id(client_id), public_key_hex);
    return response.status == 200;
}

std::optional<std::string> CommunicationTransport::get_public_key(const std::string& peer_id) const {
    auto response = request("GET", base_url_ + "/public-key/" + check_client_id(peer_id));
    if (response.status == 404) return std::nullopt;
    if (response.status != 200) throw std::runtime_error("Relay failed to return peer public key");
    while (!response.body.empty() && (response.body.back() == '\n' || response.body.back() == '\r'))
        response.body.pop_back();
    return response.body;
}

void CommunicationTransport::send_packet(const std::string& sender_id,
                                          const std::string& recipient_id,
                                          const Packet& packet) const {
    const std::string body = to_hex(packet.nonce.data(), packet.nonce.size()) + "\n" +
        to_hex(packet.tag.data(), packet.tag.size()) + "\n" +
        to_hex(packet.ciphertext.data(), packet.ciphertext.size());
    const auto response = request("POST", base_url_ + "/message/" + check_client_id(sender_id) +
                                   "/" + check_client_id(recipient_id), body);
    if (response.status != 200) throw std::runtime_error("Relay rejected encrypted packet");
}

std::vector<IncomingMessage> CommunicationTransport::receive_packets(const std::string& client_id) const {
    const auto response = request("GET", base_url_ + "/messages/" + check_client_id(client_id));
    if (response.status == 204 || response.body.empty()) return {};
    if (response.status != 200) throw std::runtime_error("Relay failed to return pending packets");
    std::vector<IncomingMessage> messages;
    std::istringstream lines(response.body);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty()) continue;
        std::istringstream fields(line);
        std::string sender, nonce_hex, tag_hex, cipher_hex;
        if (!std::getline(fields, sender, '\t') || !std::getline(fields, nonce_hex, '\t') ||
            !std::getline(fields, tag_hex, '\t') || !std::getline(fields, cipher_hex))
            throw std::runtime_error("Malformed packet record from relay");
        const auto nonce = from_hex(nonce_hex);
        const auto tag = from_hex(tag_hex);
        if (nonce.size() != kNonceBytes || tag.size() != kTagBytes)
            throw std::runtime_error("Relay packet has invalid nonce or tag length");
        IncomingMessage message;
        message.sender_id = sender;
        std::copy(nonce.begin(), nonce.end(), message.packet.nonce.begin());
        std::copy(tag.begin(), tag.end(), message.packet.tag.begin());
        message.packet.ciphertext = from_hex(cipher_hex);
        messages.push_back(std::move(message));
    }
    return messages;
}
}  // namespace demo
