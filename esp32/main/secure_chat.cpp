#include "crypto.hpp"
#include "relay_client.hpp"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "nvs_flash.h"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr char kTag[] = "ecc_chat";
constexpr EventBits_t kConnectedBit = BIT0;
constexpr EventBits_t kFailedBit = BIT1;
constexpr int kMaxWifiRetries = 10;
constexpr size_t kMaxMessageBytes = 512;

EventGroupHandle_t wifi_events;
int wifi_retries = 0;

struct EncryptedPacket {
	std::array<uint8_t, ecc_demo::kNonceBytes> nonce{};
	std::array<uint8_t, ecc_demo::kTagBytes> tag{};
	std::vector<uint8_t> ciphertext;
};

struct ReceiverState {
	ecc_demo::RelayClient* relay;
	std::string client_id;
	std::string peer_id;
	std::array<uint8_t, ecc_demo::kSessionKeyBytes> session_key;
	std::atomic<bool> running{true};
	std::atomic<bool> done{false};
};

void wifi_event_handler(void*, esp_event_base_t event_base, int32_t event_id,
						void*) {
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (wifi_retries++ < kMaxWifiRetries) {
			ESP_LOGW(kTag, "Wi-Fi disconnected; reconnecting (%d/%d)", wifi_retries,
					 kMaxWifiRetries);
			esp_wifi_connect();
		} else {
			xEventGroupSetBits(wifi_events, kFailedBit);
		}
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		wifi_retries = 0;
		xEventGroupSetBits(wifi_events, kConnectedBit);
	}
}

bool connect_wifi() {
	if (std::strlen(CONFIG_ECCCHAT_WIFI_SSID) == 0) {
		ESP_LOGE(kTag, "Set the 2.4 GHz Wi-Fi SSID in idf.py menuconfig first");
		return false;
	}
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();
	wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&init_config));
	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
												  &wifi_event_handler, nullptr));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
												  &wifi_event_handler, nullptr));

	wifi_config_t station_config{};
	std::snprintf(reinterpret_cast<char*>(station_config.sta.ssid),
				  sizeof(station_config.sta.ssid), "%s", CONFIG_ECCCHAT_WIFI_SSID);
	std::snprintf(reinterpret_cast<char*>(station_config.sta.password),
				  sizeof(station_config.sta.password), "%s", CONFIG_ECCCHAT_WIFI_PASSWORD);
	station_config.sta.threshold.authmode =
		std::strlen(CONFIG_ECCCHAT_WIFI_PASSWORD) == 0 ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
	station_config.sta.pmf_cfg.capable = true;
	station_config.sta.pmf_cfg.required = false;

	wifi_events = xEventGroupCreate();
	if (wifi_events == nullptr) return false;
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &station_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGI(kTag, "Connecting to Wi-Fi network '%s'", CONFIG_ECCCHAT_WIFI_SSID);
	const EventBits_t result = xEventGroupWaitBits(
		wifi_events, kConnectedBit | kFailedBit, pdFALSE, pdFALSE, pdMS_TO_TICKS(45000));
	if ((result & kConnectedBit) == 0) {
		ESP_LOGE(kTag, "Could not connect to Wi-Fi within 45 seconds");
		return false;
	}
	return true;
}

std::string to_hex(const uint8_t* bytes, size_t length) {
	static constexpr char digits[] = "0123456789abcdef";
	std::string result(length * 2, '0');
	for (size_t i = 0; i < length; ++i) {
		result[2 * i] = digits[bytes[i] >> 4];
		result[2 * i + 1] = digits[bytes[i] & 0x0f];
	}
	return result;
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& bytes) {
	if ((hex.size() & 1U) != 0) return false;
	auto nibble = [](char ch) -> int {
		if (ch >= '0' && ch <= '9') return ch - '0';
		if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
		if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
		return -1;
	};
	bytes.resize(hex.size() / 2);
	for (size_t i = 0; i < bytes.size(); ++i) {
		const int hi = nibble(hex[2 * i]);
		const int lo = nibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0) return false;
		bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
	}
	return true;
}

bool split_packet_line(const std::string& line, std::string& sender,
					   EncryptedPacket& packet) {
	std::istringstream fields(line);
	std::string nonce_hex, tag_hex, ciphertext_hex;
	if (!std::getline(fields, sender, '\t') ||
		!std::getline(fields, nonce_hex, '\t') ||
		!std::getline(fields, tag_hex, '\t') ||
		!std::getline(fields, ciphertext_hex)) return false;
	std::vector<uint8_t> nonce, tag;
	if (!from_hex(nonce_hex, nonce) || nonce.size() != packet.nonce.size() ||
		!from_hex(tag_hex, tag) || tag.size() != packet.tag.size() ||
		!from_hex(ciphertext_hex, packet.ciphertext) ||
		packet.ciphertext.empty() || packet.ciphertext.size() > kMaxMessageBytes) return false;
	std::copy(nonce.begin(), nonce.end(), packet.nonce.begin());
	std::copy(tag.begin(), tag.end(), packet.tag.begin());
	return true;
}

void poll_messages(void* context) {
	auto* state = static_cast<ReceiverState*>(context);
	std::string path = "/messages/" + state->client_id;
	while (state->running.load()) {
		const auto reply = state->relay->get(path);
		if (reply.status == 200) {
			std::istringstream lines(reply.body);
			std::string line;
			while (std::getline(lines, line)) {
				if (line.empty()) continue;
				std::string sender;
				EncryptedPacket packet;
				if (!split_packet_line(line, sender, packet)) {
					std::printf("\n[rejected] Malformed relay packet\n> ");
					std::fflush(stdout);
					continue;
				}
				if (sender != state->peer_id) {
					std::printf("\n[rejected] Unexpected sender %s\n> ", sender.c_str());
					std::fflush(stdout);
					continue;
				}
				std::vector<uint8_t> plaintext(packet.ciphertext.size());
				const int rc = ecc_demo::decrypt_gcm(
					state->session_key.data(), packet.ciphertext.data(),
					packet.ciphertext.size(), packet.nonce.data(), packet.tag.data(),
					plaintext.data());
				if (rc == 0) {
					std::printf("\n%s: %.*s\n> ", sender.c_str(),
							static_cast<int>(plaintext.size()),
							reinterpret_cast<const char*>(plaintext.data()));
				} else {
					std::printf("\n[rejected] AES-GCM authentication failed\n> ");
				}
				std::fflush(stdout);
			}
		} else if (reply.status != 204) {
			ESP_LOGW(kTag, "Message poll returned HTTP %d", reply.status);
		}
		vTaskDelay(pdMS_TO_TICKS(reply.status == 200 || reply.status == 204 ? 350 : 1500));
	}
	mbedtls_platform_zeroize(state->session_key.data(), state->session_key.size());
	state->done = true;
	vTaskDelete(nullptr);
}

bool establish_session(ecc_demo::Rng& rng, ecc_demo::KeyPair& key_pair,
					   ecc_demo::RelayClient& relay, const std::string& client_id,
					   const std::string& peer_id,
					   std::array<uint8_t, ecc_demo::kSessionKeyBytes>& session_key,
					   std::array<uint8_t, 32>& shared_secret) {
	std::array<uint8_t, ecc_demo::kPublicKeyBytes> public_wire{};
	int rc = ecc_demo::generate_key_pair(rng, key_pair);
	if (rc == 0) rc = ecc_demo::encode_public_key(key_pair, public_wire);
	if (rc != 0) {
		ESP_LOGE(kTag, "P-256 key generation failed: -0x%04x",
				 static_cast<unsigned>(-rc));
		return false;
	}
	const std::string public_hex = to_hex(public_wire.data(), public_wire.size());
	const auto registered = relay.post("/register/" + client_id, public_hex);
	if (registered.status != 200) {
		ESP_LOGE(kTag, "Public-key registration failed (HTTP %d)", registered.status);
		return false;
	}
	ESP_LOGI(kTag, "Public key registered as '%s'; waiting for '%s'", client_id.c_str(),
			 peer_id.c_str());

	std::string peer_key_hex;
	for (int attempt = 0; attempt < 120; ++attempt) {
		const auto response = relay.get("/public-key/" + peer_id);
		if (response.status == 200) {
			peer_key_hex = response.body;
			while (!peer_key_hex.empty() &&
				   (peer_key_hex.back() == '\n' || peer_key_hex.back() == '\r'))
				peer_key_hex.pop_back();
			break;
		}
		if (response.status != 404)
			ESP_LOGW(kTag, "Peer-key lookup returned HTTP %d", response.status);
		vTaskDelay(pdMS_TO_TICKS(500));
	}
	std::vector<uint8_t> peer_wire;
	if (peer_key_hex.empty() || !from_hex(peer_key_hex, peer_wire) ||
		peer_wire.size() != ecc_demo::kPublicKeyBytes) {
		ESP_LOGE(kTag, "Peer public key did not arrive or had an invalid encoding");
		return false;
	}
	mbedtls_ecp_group peer_group;
	mbedtls_ecp_point peer_point;
	mbedtls_ecp_group_init(&peer_group);
	mbedtls_ecp_point_init(&peer_point);
	rc = ecc_demo::decode_public_key(peer_wire.data(), peer_wire.size(), peer_group,
									 peer_point);
	if (rc == 0) rc = ecc_demo::derive_shared_secret(rng, key_pair, peer_group,
												peer_point, shared_secret);
	if (rc == 0) rc = ecc_demo::derive_session_key(
		shared_secret.data(), shared_secret.size(), nullptr, 0, session_key);
	mbedtls_ecp_point_free(&peer_point);
	mbedtls_ecp_group_free(&peer_group);
	if (rc != 0) {
		ESP_LOGE(kTag, "Peer-key validation or session derivation failed: -0x%04x",
				 static_cast<unsigned>(-rc));
		return false;
	}
	ESP_LOGI(kTag, "ECDH and HKDF session established with '%s'", peer_id.c_str());
	return true;
}

}  // namespace

namespace {
void run_chat() {
	if (!connect_wifi()) return;
	char relay_url[96];
	std::snprintf(relay_url, sizeof(relay_url), "http://%s:%d",
				  CONFIG_ECCCHAT_RELAY_HOST, CONFIG_ECCCHAT_RELAY_PORT);
	ESP_LOGI(kTag, "Using laptop relay at %s", relay_url);
	ecc_demo::RelayClient relay(relay_url);
	ecc_demo::Rng rng;
	ecc_demo::KeyPair key_pair;
	int rc = rng.seed();
	if (rc != 0) {
		ESP_LOGE(kTag, "Secure random generator initialization failed: -0x%04x",
				 static_cast<unsigned>(-rc));
		return;
	}
	std::array<uint8_t, ecc_demo::kSessionKeyBytes> session_key{};
	std::array<uint8_t, 32> shared_secret{};
	if (!establish_session(rng, key_pair, relay, CONFIG_ECCCHAT_CLIENT_ID,
						   CONFIG_ECCCHAT_PEER_ID, session_key, shared_secret)) return;
	mbedtls_platform_zeroize(shared_secret.data(), shared_secret.size());

	ReceiverState receiver{&relay, CONFIG_ECCCHAT_CLIENT_ID,
						CONFIG_ECCCHAT_PEER_ID, session_key};
	TaskHandle_t receiver_task = nullptr;
	if (xTaskCreate(poll_messages, "chat_rx", 10240, &receiver, 5,
					&receiver_task) != pdPASS) {
		mbedtls_platform_zeroize(session_key.data(), session_key.size());
		ESP_LOGE(kTag, "Could not start the receive task");
		return;
	}
	std::printf("\nESP32 chat is ready. Type a message and press Enter; /quit ends the session.\n> ");
	std::fflush(stdout);
	// Read the USB-UART console directly. stdio fgets() can report EOF on some
	// ESP-IDF console configurations, which would otherwise end the chat at once.
	const esp_err_t uart_result = uart_driver_install(UART_NUM_0, 2048, 0, 0, nullptr, 0);
	if (uart_result != ESP_OK && uart_result != ESP_ERR_INVALID_STATE) {
		ESP_LOGE(kTag, "Could not initialize UART console input: %s",
				esp_err_to_name(uart_result));
		receiver.running = false;
		while (!receiver.done.load()) vTaskDelay(pdMS_TO_TICKS(100));
		mbedtls_platform_zeroize(session_key.data(), session_key.size());
		return;
	}
	char input[kMaxMessageBytes + 1]{};
	size_t input_length = 0;
	while (true) {
		uint8_t ch = 0;
		if (uart_read_bytes(UART_NUM_0, &ch, 1, portMAX_DELAY) <= 0) continue;
		if (ch == '\r') continue;
		if (ch != '\n') {
			if (input_length < kMaxMessageBytes) input[input_length++] = static_cast<char>(ch);
			continue;
		}
		std::string message(input, input_length);
		input_length = 0;
		input[0] = '\0';
		if (message == "/quit") break;
		if (message.empty()) {
			std::printf("> ");
			std::fflush(stdout);
			continue;
		}
		if (message.size() > kMaxMessageBytes) {
			std::printf("Message too long (maximum %u bytes).\n> ",
						static_cast<unsigned>(kMaxMessageBytes));
			std::fflush(stdout);
			continue;
		}
		std::vector<uint8_t> ciphertext(message.size());
		std::array<uint8_t, ecc_demo::kNonceBytes> nonce{};
		std::array<uint8_t, ecc_demo::kTagBytes> tag{};
		rc = ecc_demo::encrypt_gcm(
			rng, session_key.data(), reinterpret_cast<const uint8_t*>(message.data()),
			message.size(), ciphertext.data(), nonce, tag);
		if (rc == 0) {
			const std::string payload = to_hex(nonce.data(), nonce.size()) + "\n" +
				to_hex(tag.data(), tag.size()) + "\n" +
				to_hex(ciphertext.data(), ciphertext.size());
			const auto sent = relay.post("/message/" +
				std::string(CONFIG_ECCCHAT_CLIENT_ID) + "/" + CONFIG_ECCCHAT_PEER_ID,
				payload);
			if (sent.status == 200) {
				std::printf("[sent securely]\n");
			} else {
				std::printf("[send failed: relay HTTP %d]\n", sent.status);
			}
		} else {
			std::printf("[encryption failed: -0x%04x]\n",
						static_cast<unsigned>(-rc));
		}
		std::printf("> ");
		std::fflush(stdout);
	}
	receiver.running = false;
	for (int wait = 0; wait < 90 && !receiver.done.load(); ++wait)
		vTaskDelay(pdMS_TO_TICKS(100));
	if (!receiver.done.load()) {
		ESP_LOGW(kTag, "Receive task did not stop promptly; it will finish after its HTTP request");
		// Keep the app task alive until the receive task releases its own state.
		while (!receiver.done.load()) vTaskDelay(pdMS_TO_TICKS(100));
	}
	mbedtls_platform_zeroize(session_key.data(), session_key.size());
	mbedtls_mpi_lset(&key_pair.private_scalar, 0);
	std::printf("\nESP32 chat session ended.\n");
}
}  // namespace

extern "C" void app_main(void) {
	// Keep Wi-Fi, ECC and HTTP work off ESP-IDF's small default main-task stack.
	constexpr uint32_t kChatTaskStackBytes = 16 * 1024;
	if (xTaskCreate([](void*) {
			run_chat();
			vTaskDelete(nullptr);
		}, "ecc_chat", kChatTaskStackBytes, nullptr, 5, nullptr) != pdPASS) {
		ESP_LOGE(kTag, "Could not create the chat task");
	}
}
