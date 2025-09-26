#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetParsedTlsRecordFromEthernet ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto packet = packet_data[ 18 ];
	auto result = ntk::get_parsed_tls_record_from_ethernet( packet );
	ASSERT_FALSE( result );
}

TEST( UnitTest, GetParsedTlsRecordFromEthernet_LongStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto packet = packet_data[ 13 ];
	auto record = ntk::get_parsed_tls_record_from_ethernet( packet );
	ASSERT_TRUE( record );
}

