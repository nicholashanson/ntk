#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpStatusLine ) {
    auto payload_result = ntk::get_tcp_payload( test::http_response_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_http_payload( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto& split_http_message = split_result.value();
    auto& raw_status_line = split_http_message.start_line;
    auto parse_result = ntk::parse_http_status_line( raw_status_line );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    auto& status_line = parse_result.value();
    EXPECT_EQ( status_line.status_code, 200 ); 
}