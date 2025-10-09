#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <array>
#include <expected>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

namespace ntk {

	struct x25519_key_pair {
        std::array<uint8_t,32> private_key;
        std::array<uint8_t,32> public_key;
    };

	std::expected<x25519_key_pair,std::string> generate_x25519_key_pair();

	std::expected<std::vector<uint8_t>,std::string> derive_x25519_shared_secret( const std::array<uint8_t,32>& private_key,
                                                                                 const std::array<uint8_t,32>& peer_public_key );
} // namespace ntk

#endif // CRYPTO_HPP