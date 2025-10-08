#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetRawTcpStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    ASSERT_EQ( raw_stream.size(), 2 );
}
