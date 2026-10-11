#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

namespace demo {
    using BigInt = boost::multiprecision::cpp_int;
    constexpr size_t kPointBytes = 65;
    constexpr size_t kSecretBytes = 32;

    struct Point {
        BigInt x = 0;
        BigInt y = 0;
        bool infinity = true;
    };
    struct KeyPair {
        BigInt private_scalar;
        Point public_point;
    };

    const BigInt& field_prime();
    const BigInt& curve_order();
    Point generator_point();
    bool is_on_curve(const Point& point);
    Point add_points(const Point& left, const Point& right);
    Point multiply_point(const BigInt& scalar, const Point& point);
    KeyPair generate_key_pair();
    std::array<uint8_t, kPointBytes> encode_public_key(const Point& point);
    Point decode_public_key(const uint8_t* bytes, size_t length);
    std::array<uint8_t, kSecretBytes> derive_shared_secret(const BigInt& private_scalar,
                                                        const Point& peer_public);
}  // namespace demo
