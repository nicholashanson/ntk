#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpResponse_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_response_packet( std::span( test::http_response_packet ) ) );
}

TEST( UnitTest, IsHttpResponse_TcpPayload ) {
	auto http_payload = ntk::get_tcp_payload( test::http_response_packet );
	ASSERT_TRUE( ntk::is_http_response( http_payload ) ); 
}