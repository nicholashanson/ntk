#include <gtest/gtest.h>

#include <http.hpp>

#include <qt.hpp>
#include <test_constants.hpp>

TEST( VisualTest, Text ) {
    auto payload_result = ntk::get_tcp_payload( test::http_response_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty";
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_http_payload( payload );
    ASSERT_TRUE( split_result ) <<  split_result.error() << std::endl;
    auto& split_http_message = *split_result;
    auto& http_content = split_http_message.body; 
    EXPECT_FALSE( http_content.empty() );
    auto dechunked_http_content = ntk::decode_single_chunk( http_content ); 
    std::string http_content_string( dechunked_http_content.begin(), dechunked_http_content.end() );
    test::show_text_in_qt_window( QString::fromStdString( http_content_string ) );
}