#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, SplitHttpPayload ) {
    auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_http_payload( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto split_http_message = split_result.value(); 
    ASSERT_EQ( split_http_message.start_line.size(), 14 );
    ASSERT_EQ( split_http_message.headers.size(), 334 );
    ASSERT_EQ( split_http_message.body.size(), 0 );
}
