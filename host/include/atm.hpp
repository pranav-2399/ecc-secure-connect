#pragma once

#include <cstdint>
#include <string>

namespace demo {

enum class WithdrawalStatus {
	approved,
	invalid_pin,
	locked,
	insufficient_funds,
	invalid_amount
};

struct WithdrawalResult {
	WithdrawalStatus status;
	int attempts_remaining;
	int64_t balance;
};

WithdrawalResult process_withdrawal(const std::string& account_id,
									const std::string& expected_pin,
									const std::string& supplied_pin,
									int64_t amount);
void unlock_account(const std::string& account_id);

}  // namespace demo
