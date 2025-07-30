#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpRequest_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_request_packet( std::span( test::http_get_packet ) ) );
}

TEST( UnitTest, IsHttpRequest_TcpPayload ) {
	auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
	ASSERT_TRUE( ntk::is_http_request( http_payload ) ); 
}