#include <gtest/gtest.h>

#include <vector>

#include <tcp.hpp>
#include <http.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, EndsWithZeroChunk ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    EXPECT_TRUE( ntk::ends_with_zero_chunk( tcp_stream ) ) << "Last TCP segment does not end with a zero chunk.";
    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );
    EXPECT_TRUE( ntk::ends_with_zero_chunk( merged_tcp_stream ) ) << "Last TCP segment does not end with a zero chunk.";
}

TEST( UnitTest, EndsWithZeroChunk_Body ) {
    std::vector<uint8_t> body = {
         '4', '\r', '\n',
         't',  'e',  's', 't', '\r', '\n',
         '0', '\r', '\n',
        '\r', '\n'
    };
    EXPECT_TRUE( ntk::ends_with_zero_chunk( body ) );
}
