#include "atm.hpp"

#include <openssl/crypto.h>
#include <sqlite3.h>

#include <cstdlib>
#include <cerrno>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace demo {
namespace {
constexpr int kMaxPinAttempts = 3;
constexpr int64_t kDefaultInitialBalance = 50000;

const char* env_or(const char* name, const char* fallback) {
	const char* value = std::getenv(name);
	return value != nullptr && value[0] != '\0' ? value : fallback;
}

int64_t initial_balance() {
	const char* raw = std::getenv("ECC_ATM_INITIAL_BALANCE");
	if (raw == nullptr || raw[0] == '\0') return kDefaultInitialBalance;
	errno = 0;
	char* end = nullptr;
	const long long value = std::strtoll(raw, &end, 10);
	if (errno == ERANGE || end == raw || *end != '\0' || value < 0 ||
		value > std::numeric_limits<int64_t>::max())
		throw std::runtime_error("ECC_ATM_INITIAL_BALANCE must be a non-negative whole number");
	return static_cast<int64_t>(value);
}

class Database {
public:
	Database() {
		const int rc = sqlite3_open_v2(env_or("ECC_ATM_DB", "atm_demo.sqlite3"), &db_,
			SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
		if (rc != SQLITE_OK) {
			const std::string error = db_ ? sqlite3_errmsg(db_) : "allocation failed";
			if (db_) sqlite3_close(db_);
			db_ = nullptr;
			throw std::runtime_error("ATM database open failed: " + error);
		}
		sqlite3_busy_timeout(db_, 3000);
		exec("PRAGMA journal_mode=WAL");
		exec("CREATE TABLE IF NOT EXISTS accounts ("
			 "account_id TEXT PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance >= 0),"
			 "failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0),"
			 "locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0,1)))");
		exec("CREATE TABLE IF NOT EXISTS withdrawals ("
			 "id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,"
			 "amount INTEGER NOT NULL CHECK(amount > 0), balance_after INTEGER NOT NULL,"
			 "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
	}
	~Database() { if (db_) sqlite3_close(db_); }
	Database(const Database&) = delete;
	Database& operator=(const Database&) = delete;

	sqlite3* get() const { return db_; }
	void exec(const char* sql) {
		char* error = nullptr;
		if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
			const std::string message = error ? error : sqlite3_errmsg(db_);
			sqlite3_free(error);
			throw std::runtime_error("ATM database operation failed: " + message);
		}
	}

private:
	sqlite3* db_ = nullptr;
};

class Statement {
public:
	Statement(sqlite3* db, const char* sql) : db_(db) {
		if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK)
			throw std::runtime_error(std::string("ATM database query failed: ") + sqlite3_errmsg(db));
	}
	~Statement() { sqlite3_finalize(statement_); }
	Statement(const Statement&) = delete;
	Statement& operator=(const Statement&) = delete;
	sqlite3_stmt* get() const { return statement_; }
	void bind_text(int index, const std::string& value) {
		if (sqlite3_bind_text(statement_, index, value.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK)
			throw std::runtime_error(std::string("ATM database bind failed: ") + sqlite3_errmsg(db_));
	}
	void bind_int64(int index, int64_t value) {
		if (sqlite3_bind_int64(statement_, index, value) != SQLITE_OK)
			throw std::runtime_error(std::string("ATM database bind failed: ") + sqlite3_errmsg(db_));
	}
	void run() {
		if (sqlite3_step(statement_) != SQLITE_DONE)
			throw std::runtime_error(std::string("ATM database update failed: ") + sqlite3_errmsg(db_));
	}

private:
	sqlite3* db_;
	sqlite3_stmt* statement_ = nullptr;
};

void ensure_account(Database& db, const std::string& account_id) {
	Statement statement(db.get(), "INSERT OR IGNORE INTO accounts(account_id,balance) VALUES(?,?)");
	statement.bind_text(1, account_id);
	statement.bind_int64(2, initial_balance());
	statement.run();
}

struct AccountState { int64_t balance; int attempts; bool locked; };
AccountState load_account(Database& db, const std::string& account_id) {
	Statement statement(db.get(), "SELECT balance,failed_attempts,locked FROM accounts WHERE account_id=?");
	statement.bind_text(1, account_id);
	if (sqlite3_step(statement.get()) != SQLITE_ROW)
		throw std::runtime_error("ATM account state is unavailable");
	return {sqlite3_column_int64(statement.get(), 0), sqlite3_column_int(statement.get(), 1),
			sqlite3_column_int(statement.get(), 2) != 0};
}

bool pin_matches(const std::string& expected, const std::string& supplied) {
	if (expected.size() != supplied.size()) return false;
	return CRYPTO_memcmp(expected.data(), supplied.data(), expected.size()) == 0;
}

void update_auth_state(Database& db, const std::string& account_id, int attempts, bool locked) {
	Statement statement(db.get(), "UPDATE accounts SET failed_attempts=?,locked=? WHERE account_id=?");
	statement.bind_int64(1, attempts);
	statement.bind_int64(2, locked ? 1 : 0);
	statement.bind_text(3, account_id);
	statement.run();
}

void begin(Database& db) { db.exec("BEGIN IMMEDIATE"); }
void commit(Database& db) { db.exec("COMMIT"); }
void rollback(Database& db) noexcept { sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr); }

}  // namespace

WithdrawalResult process_withdrawal(const std::string& account_id,
									const std::string& expected_pin,
									const std::string& supplied_pin,
									int64_t amount) {
	Database db;
	ensure_account(db, account_id);
	begin(db);
	try {
		AccountState state = load_account(db, account_id);
		if (state.locked) {
			commit(db);
			return {WithdrawalStatus::locked, 0, state.balance};
		}
		if (!pin_matches(expected_pin, supplied_pin)) {
			const int attempts = state.attempts + 1;
			const bool locked = attempts >= kMaxPinAttempts;
			update_auth_state(db, account_id, attempts, locked);
			commit(db);
			return {locked ? WithdrawalStatus::locked : WithdrawalStatus::invalid_pin,
					kMaxPinAttempts - attempts, state.balance};
		}
		update_auth_state(db, account_id, 0, false);
		if (amount < 100 || amount > 10000 || amount % 100 != 0) {
			commit(db);
			return {WithdrawalStatus::invalid_amount, kMaxPinAttempts, state.balance};
		}
		if (state.balance < amount) {
			commit(db);
			return {WithdrawalStatus::insufficient_funds, kMaxPinAttempts, state.balance};
		}
		Statement debit(db.get(), "UPDATE accounts SET balance=balance-? WHERE account_id=? AND balance>=?");
		debit.bind_int64(1, amount);
		debit.bind_text(2, account_id);
		debit.bind_int64(3, amount);
		debit.run();
		if (sqlite3_changes(db.get()) != 1) throw std::runtime_error("Withdrawal debit was not applied");
		const int64_t new_balance = state.balance - amount;
		Statement receipt(db.get(), "INSERT INTO withdrawals(account_id,amount,balance_after) VALUES(?,?,?)");
		receipt.bind_text(1, account_id);
		receipt.bind_int64(2, amount);
		receipt.bind_int64(3, new_balance);
		receipt.run();
		commit(db);
		return {WithdrawalStatus::approved, kMaxPinAttempts, new_balance};
	} catch (...) {
		rollback(db);
		throw;
	}
}

void unlock_account(const std::string& account_id) {
	Database db;
	ensure_account(db, account_id);
	Statement statement(db.get(), "UPDATE accounts SET failed_attempts=0,locked=0 WHERE account_id=?");
	statement.bind_text(1, account_id);
	statement.run();
}

}  // namespace demo
