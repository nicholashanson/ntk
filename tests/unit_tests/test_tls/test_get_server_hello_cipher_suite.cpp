#include <gtest/gtest.h>

#include <cstdint>

#include <tls.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetServerHelloCipherSuite ) {
	const std::size_t cipher_suite_pos = 76;
	auto result = ntk::get_server_hello_cipher_suite( test_constants::tls_server_hello_record, cipher_suite_pos );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto expected_cipher_suite = static_cast<uint16_t>( ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
	ASSERT_EQ( result.value(), expected_cipher_suite );
}