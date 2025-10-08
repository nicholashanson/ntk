#include <gtest/gtest.h>

#include <algorithm>

#include <tcp.hpp>
#include <http.hpp>
#include <io.hpp>

#include <qt.hpp>
#include <test_constants.hpp>

TEST( VisualTest, TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    auto response = *std::find_if( tcp_stream.begin(), tcp_stream.end(), 
        [] ( const auto& pair ) { 
            auto& [ unused, http_payload ] = pair;
            return ntk::get_http_type( http_payload ) == ntk::http_type::response;
        } 
    );
    auto maybe_split_http_message = ntk::split_http_payload( response.second );
    ASSERT_TRUE( maybe_split_http_message );
    auto http_body = ( *maybe_split_http_message ).body;
    auto dechunked_body = ntk::decode_single_chunk( http_body );
    test::show_bitmap_in_qt_window( dechunked_body );
}