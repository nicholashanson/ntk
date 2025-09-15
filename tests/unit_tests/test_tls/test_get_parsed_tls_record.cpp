#include <gtest/gtest.h>

#include <tls.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetParsedTlsRecord ) {
	auto parse_result = ntk::get_parsed_tls_record( test_constants::tls_server_hello_record );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& record = parse_result.value();
	EXPECT_EQ( record.payload.size(), sizeof( test_constants::tls_server_hello ) );
	EXPECT_TRUE( std::equal( record.payload.begin(), record.payload.end(), test_constants::tls_server_hello ) );
}