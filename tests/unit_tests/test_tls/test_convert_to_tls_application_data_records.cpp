#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ConvertToTlsApplicationDataRecords ) {
	auto read_result = ntk::read_from_file( "http_response.txt" );
	ASSERT_TRUE( read_result ) << read_result.error();
	std::string secret_str = "c6007711e804e4c2b22755d958bdaeb40f959c1ebe8b00289388e58c40078cd8";
	auto secret_result = ntk::hex_string_to_bytes( secret_str );
	ASSERT_TRUE( secret_result ) << secret_result.error();
	auto& secret = secret_result.value();
	auto& http_message = read_result.value();
	auto ts_read_result = ntk::read_from_file( "../assets/segment.ts" );
	ASSERT_TRUE( ts_read_result ) << ts_read_result.error();
	auto& ts = ts_read_result.value();
	http_message.insert( http_message.end(), ts.begin(), ts.end() );
	uint64_t seq_num{};
	auto records_result = ntk::convert_to_tls_application_data_records( ntk::cipher_suite::TLS_AES_128_GCM_SHA256, 
																		http_message, secret, seq_num, 16385 );
	ASSERT_TRUE( records_result ) << records_result.error();
}
