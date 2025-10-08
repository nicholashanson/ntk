#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseHttpRequestLine ) {
    auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_http_payload( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto split_http_message = split_result.value();
    auto raw_request_line = split_http_message.start_line;
    auto request_line_result = ntk::parse_http_request_line( raw_request_line );
    ASSERT_TRUE( request_line_result ) << request_line_result.error() << std::endl;
    auto& request_line = request_line_result.value();
    ASSERT_EQ( request_line.method_token, "GET" );
}

TEST( UnitTest, ParseHttpRequestLine_TrailingSpace ) {
    std::vector<uint8_t> request_line = { 'G', 'E', 'T', 
        ' ', '/', 'H', 'T', 'T', 'P', 
        ' ', '/', '1', '.', '1', ' ', '\r', '\n' };
    auto parse_result = ntk::parse_http_request_line( request_line );
    ASSERT_FALSE( parse_result );
    EXPECT_EQ( parse_result.error(), ntk::http_parse_error::trailing_content );
}
