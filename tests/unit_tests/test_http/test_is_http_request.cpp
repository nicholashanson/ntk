#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpRequest_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_request_packet( std::span( test::http_get_packet ) ) );
}

TEST( UnitTest, IsHttpRequest_TcpPayload ) {
	auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
	ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
	ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
	auto& payload = *payload_result.value();
	ASSERT_TRUE( ntk::is_http_request( payload ) ); 
}