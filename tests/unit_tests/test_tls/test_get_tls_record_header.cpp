#include <gtest/gtest.h>

#include <algorithm>

#include <tls.hpp>
#include <io.hpp>    

#include <test_constants.hpp>

TEST( UnitTest, GetTlsRecordHeader ) {
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
	std::array<uint8_t,5> header_bytes;
	std::copy_n( payload.begin(), header_bytes.size(), header_bytes.begin() );
	auto actual_record_header = ntk::get_tls_record_header( header_bytes );
	ASSERT_EQ( actual_record_header, expected_record_header );
}

TEST( UnitTest, GetTlsRecordHeader_ClientHello ) {
	constexpr ntk::tls_record_header expected_record_header = {
    	ntk::tls_content_type::handshake,  
    	ntk::tls_version::tls_1_0,      
    	static_cast<uint16_t>( 0x0144 )               
	};
	const std::array<uint8_t,5> header_bytes = { 0x16, 0x03, 0x01, 0x01, 0x44 }; 
	auto result = ntk::get_tls_record_header( header_bytes );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_EQ( result.value(), expected_record_header );
}


