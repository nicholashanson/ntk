#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetEmptyTlsRecordFromEthernet ) {
	const ntk::tls_record expected_empty_record = {
    	static_cast<ntk::tls_content_type>( 0x17 ),   
    	static_cast<ntk::tls_version>( 0x0303 ),      
    	std::vector<uint8_t>{}              
	};
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto packet = packet_data[ 18 /* http request */ ];
	auto actual_empty_record = ntk::get_empty_tls_record_from_ethernet( packet );
	ASSERT_EQ( actual_empty_record, expected_empty_record );
}