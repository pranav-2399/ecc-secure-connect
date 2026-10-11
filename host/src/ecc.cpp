#include "ecc.hpp"

#include <openssl/rand.h>
#include <stdexcept>

namespace demo {
	namespace {
		const BigInt kP("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
		const BigInt kA("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
		const BigInt kB("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
		const BigInt kN("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
		const Point kG{
			BigInt("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
			BigInt("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
			false
		};

		BigInt mod(BigInt value) {
			value %= kP;
			if (value < 0) value += kP;
			return value;
		}

		BigInt inverse(const BigInt& value) {
			if (mod(value) == 0) throw std::runtime_error("ECC division by zero");
			return boost::multiprecision::powm(mod(value), kP - 2, kP);
		}

		BigInt from_bytes(const uint8_t* bytes, size_t length) {
			BigInt value = 0;
			for (size_t i = 0; i < length; ++i) value = (value << 8) | bytes[i];
			return value;
		}

		void to_32_bytes(const BigInt& value, uint8_t* output) {
			BigInt copy = value;
			for (int i = 31; i >= 0; --i) {
				output[i] = static_cast<uint8_t>(copy & 0xff);
				copy >>= 8;
			}
		}
	}  // namespace

	const BigInt& field_prime() { return kP; }
	const BigInt& curve_order() { return kN; }
	Point generator_point() { return kG; }

	bool is_on_curve(const Point& point) {
		if (point.infinity) return true;
		if (point.x < 0 || point.x >= kP || point.y < 0 || point.y >= kP) return false;
		return mod(point.y * point.y) == mod(point.x * point.x * point.x + kA * point.x + kB);
	}

	Point add_points(const Point& left, const Point& right) {
		if (left.infinity) return right;
		if (right.infinity) return left;
		if (!is_on_curve(left) || !is_on_curve(right)) throw std::runtime_error("Point is not on P-256");
		if (left.x == right.x && mod(left.y + right.y) == 0) return {};

		BigInt slope;
		if (left.x == right.x && left.y == right.y) {
			if (left.y == 0) return {};
			slope = mod((3 * left.x * left.x + kA) * inverse(2 * left.y));
		} else {
			slope = mod((right.y - left.y) * inverse(right.x - left.x));
		}

		const BigInt x3 = mod(slope * slope - left.x - right.x);
		const BigInt y3 = mod(slope * (left.x - x3) - left.y);
		Point result{x3, y3, false};
		if (!is_on_curve(result)) throw std::runtime_error("ECC point arithmetic failed curve check");

		return result;
	}

	Point multiply_point(const BigInt& scalar, const Point& point) {
		if (scalar < 0 || !is_on_curve(point)) throw std::runtime_error("Invalid scalar or point");

		Point result;
		Point addend = point;
		BigInt remaining = scalar;

		while (remaining > 0) {
			if ((remaining & 1) != 0) result = add_points(result, addend);
			remaining >>= 1;
			if (remaining != 0) addend = add_points(addend, addend);
		}

		return result;
	}

	KeyPair generate_key_pair() {
		// Rejection sampling produces a uniformly distributed scalar in [1, n-1].
		std::array<uint8_t, 32> candidate{};
		BigInt private_scalar;

		do {
			if (RAND_bytes(candidate.data(), candidate.size()) != 1)
				throw std::runtime_error("OpenSSL secure random generator failed");
			private_scalar = from_bytes(candidate.data(), candidate.size());
		} while (private_scalar == 0 || private_scalar >= kN);

		OPENSSL_cleanse(candidate.data(), candidate.size());
		Point public_point = multiply_point(private_scalar, kG);
		if (!is_on_curve(public_point)) throw std::runtime_error("Generated public key is invalid");

		return {private_scalar, public_point};
	}

	std::array<uint8_t, kPointBytes> encode_public_key(const Point& point) {
		if (point.infinity || !is_on_curve(point)) throw std::runtime_error("Cannot encode invalid public key");
		
		std::array<uint8_t, kPointBytes> output{};
		output[0] = 0x04;
		to_32_bytes(point.x, output.data() + 1);
		to_32_bytes(point.y, output.data() + 33);

		return output;
	}

	Point decode_public_key(const uint8_t* bytes, size_t length) {
		if (bytes == nullptr || length != kPointBytes || bytes[0] != 0x04)
			throw std::runtime_error("Expected 65-byte uncompressed SEC1 P-256 point");

		Point point{from_bytes(bytes + 1, 32), from_bytes(bytes + 33, 32), false};
		if (!is_on_curve(point)) throw std::runtime_error("Peer public key is not on P-256");

		return point;
	}

	std::array<uint8_t, kSecretBytes> derive_shared_secret(const BigInt& private_scalar, const Point& peer_public) {
		if (private_scalar <= 0 || private_scalar >= kN || !is_on_curve(peer_public) || peer_public.infinity)
			throw std::runtime_error("Invalid ECDH input");

		Point shared = multiply_point(private_scalar, peer_public);
		if (shared.infinity) throw std::runtime_error("ECDH produced point at infinity");

		std::array<uint8_t, kSecretBytes> output{};
		to_32_bytes(shared.x, output.data());
		return output;
	}
}  // namespace demo
