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
	auto& packet = packet_data[ 18 ];
	auto payload_result = ntk::get_tcp_payload( packet );
	ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
	ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
	auto& payload = *payload_result.value();
	auto record_result = ntk::get_tls_record_header_from_payload( payload );
	ASSERT_TRUE( record_result ) << record_result.error() << std::endl;
	ASSERT_EQ( record_result.value(), expected_record_header );
}