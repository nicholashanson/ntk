#include <gtest/gtest.h>

#include <tcp.hpp>
#include <http.hpp>
#include <io.hpp>

#include <qt.hpp>
#include <test_constants.hpp>

TEST( VisualTest, Lena ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );
    std::vector<uint8_t> lena_image;
    for ( auto& [ sequence_number, tcp_body ] : merged_tcp_stream ) {
        if ( ntk::get_http_type( tcp_body ) == ntk::http_type::request ) {
            continue;
        }
        if ( ntk::get_http_type( tcp_body ) == ntk::http_type::response ) {
            auto maybe_split_http_message = ntk::split_http_payload( tcp_body );
            ASSERT_TRUE( maybe_split_http_message );
            tcp_body = ( *maybe_split_http_message ).body;
        } 
        lena_image.insert( lena_image.end(), tcp_body.begin(), tcp_body.end() );
    } 

    auto decoded_lena_image = ntk::decode_chunked_http_body( lena_image );
    std::ofstream out( "lena.bmp", std::ios::binary );
    out.write( reinterpret_cast<const char*>( decoded_lena_image.data() ), decoded_lena_image.size() );
    test::show_bitmap_in_qt_window( decoded_lena_image );
}