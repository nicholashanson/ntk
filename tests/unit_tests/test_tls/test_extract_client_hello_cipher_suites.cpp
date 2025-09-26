#include <gtest/gtest.h>

#include <tls.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, ExtractClientHelloCipherSuites ) {
	auto result = ntk::extract_client_hello_cipher_suites( test_constants::tls_client_hello_bytes, 32 /* session id len */ );
	std::vector<uint8_t> expected_bytes( std::begin( test_constants::tls_client_hello_cipher_suites), 
										 std::end( test_constants::tls_client_hello_cipher_suites ) ); 
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_EQ( result.value(), expected_bytes );
}