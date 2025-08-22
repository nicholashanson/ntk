#include <gtest/gtest.h>

#include <http.hpp>

#include <qt.hpp>
#include <test_constants.hpp>

TEST( VisualTest, Text ) {
    auto http_payload = ntk::get_tcp_payload( test::http_response_packet );
    auto maybe_split_http_message = ntk::split_http_payload( http_payload );
    ASSERT_TRUE( maybe_split_http_message );
    auto split_http_message = *maybe_split_http_message;
    auto http_content = split_http_message.body; 
    EXPECT_FALSE( http_content.empty() );
    auto dechunked_http_content = ntk::decode_single_chunk( http_content ); 
    std::string http_content_string( dechunked_http_content.begin(), dechunked_http_content.end() );
    test::show_text_in_qt_window( QString::fromStdString( http_content_string ) );
}