#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTlsRecordHeaderFromPayload ) {
	constexpr ntk::tls_record_header expected_record_header = {
    	static_cast<ntk::tls_content_type>( 0x17 ),   
    	static_cast<ntk::tls_version>( 0x0303 ),      
    	static_cast<uint16_t>( 0x4011 )               
	};
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto packet = packet_data[ 18 ];
	auto payload = ntk::get_tcp_payload( packet );
	auto actual_record_header = ntk::get_tls_record_header_from_payload( payload );
	ASSERT_EQ( actual_record_header, expected_record_header );
}