#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetCompleteOrIncompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto packet = packet_data[ 18 ];
	auto incomplete_record = ntk::get_complete_or_incomplete_record( packet );
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( incomplete_record ) );
	auto incomplete_record_ = std::get<ntk::incomplete_tls_record>( incomplete_record );
	ASSERT_EQ( incomplete_record_.record.payload.size(), 1429 );
	ASSERT_EQ( incomplete_record_.expected_payload_length, 0x4011 ); 
}

TEST( UnitTest, GetCompleteOrIncompleteRecord_CompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto packet = packet_data[ 13 ];
	auto complete_record = ntk::get_complete_or_incomplete_record( packet );
	ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( complete_record ) );
}