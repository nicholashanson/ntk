#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

TEST( UnitTest, GetRawTcpStream ) {
    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    ASSERT_EQ( raw_stream.size(), 2 );
}
