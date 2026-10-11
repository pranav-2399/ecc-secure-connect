#include "relay_client.hpp"

#include "esp_http_client.h"

namespace ecc_demo {
namespace {
esp_err_t collect_body(esp_http_client_event_t* event) {
	if (event->event_id == HTTP_EVENT_ON_DATA && event->user_data != nullptr &&
		event->data != nullptr && event->data_len > 0) {
		auto* body = static_cast<std::string*>(event->user_data);
		body->append(static_cast<const char*>(event->data), event->data_len);
	}
	return ESP_OK;
}
}  // namespace

RelayClient::RelayClient(std::string base_url) : base_url_(std::move(base_url)) {
	while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

HttpReply RelayClient::get(const std::string& path) const {
	return request(false, path, {});
}

HttpReply RelayClient::post(const std::string& path, const std::string& body) const {
	return request(true, path, body);
}

HttpReply RelayClient::request(bool is_post, const std::string& path,
							   const std::string& body) const {
	HttpReply reply;
	const std::string url = base_url_ + path;
	esp_http_client_config_t config{};
	config.url = url.c_str();
	config.timeout_ms = 7000;
	config.buffer_size = 2048;
	config.buffer_size_tx = 2048;
	config.event_handler = collect_body;
	config.user_data = &reply.body;
	esp_http_client_handle_t client = esp_http_client_init(&config);
	if (client == nullptr) return reply;

	if (is_post) {
		esp_http_client_set_method(client, HTTP_METHOD_POST);
		esp_http_client_set_header(client, "Content-Type", "text/plain; charset=utf-8");
		esp_http_client_set_post_field(client, body.data(), body.size());
	} else {
		esp_http_client_set_method(client, HTTP_METHOD_GET);
	}

	const esp_err_t err = esp_http_client_perform(client);
	if (err == ESP_OK) reply.status = esp_http_client_get_status_code(client);
	esp_http_client_cleanup(client);
	return reply;
}

}  // namespace ecc_demo
