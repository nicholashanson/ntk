#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpHeaders ) {
    auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_http_payload( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto& split_http_message = split_result.value();
    auto http_headers = ntk::parse_http_headers( split_http_message.headers );
    ASSERT_EQ( http_headers[ "Host" ], "192.168.0.21:3000" );
}