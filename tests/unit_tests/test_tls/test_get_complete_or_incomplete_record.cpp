#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetCompleteOrIncompleteRecord_IncompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto packet = packet_data[ 18 /* first part of http response */ ];
	auto parse_result = ntk::get_complete_or_incomplete_record( packet );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& record_variant = parse_result.value();
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( record_variant ) ); 
	auto& incomplete_record = std::get<ntk::incomplete_tls_record>( record_variant );  
	ASSERT_EQ( incomplete_record.record.payload.size() , 1429 );
	ASSERT_EQ( incomplete_record.expected_payload_length, 0x4011 );
}

TEST( UnitTest, GetCompleteOrIncompleteRecord_CompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto packet = packet_data[ 13 /* http request */ ];
	auto parse_result = ntk::get_complete_or_incomplete_record( packet );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& record_variant = parse_result.value();
	ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( record_variant ) );
}