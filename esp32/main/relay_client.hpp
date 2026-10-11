#pragma once

#include <string>
#include <utility>

namespace ecc_demo {

struct HttpReply {
	int status = 0;
	std::string body;
};

class RelayClient {
public:
	explicit RelayClient(std::string base_url);
	HttpReply get(const std::string& path) const;
	HttpReply post(const std::string& path, const std::string& body) const;

private:
	HttpReply request(bool is_post, const std::string& path,
					  const std::string& body) const;
	std::string base_url_;
};

}  // namespace ecc_demo
