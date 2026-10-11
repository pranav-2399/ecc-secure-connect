idf_component_register(
	SRCS "crypto.cpp" "relay_client.cpp" "secure_chat.cpp"
	INCLUDE_DIRS "."
	REQUIRES mbedtls esp_wifi esp_event esp_netif nvs_flash esp_http_client
)
