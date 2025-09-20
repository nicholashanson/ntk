#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpResponse_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_response_packet( std::span( test::http_response_packet ) ) );
}

TEST( UnitTest, IsHttpResponse_TcpPayload ) {
	auto payload_result = ntk::get_tcp_payload( test::http_response_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
	ASSERT_TRUE( ntk::is_http_response( payload ) ); 
}