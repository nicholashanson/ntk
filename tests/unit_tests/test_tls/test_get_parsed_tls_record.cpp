#include <gtest/gtest.h>

#include <tls.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetParsedTlsRecord ) {
	auto actual_tls_record = *ntk::get_parsed_tls_record( test_constants::tls_server_hello_record );
	ASSERT_EQ( actual_tls_record.payload.size(), sizeof( test_constants::tls_server_hello ) );
	ASSERT_TRUE( std::equal( actual_tls_record.payload.begin(), actual_tls_record.payload.end(), test_constants::tls_server_hello  ) );
}