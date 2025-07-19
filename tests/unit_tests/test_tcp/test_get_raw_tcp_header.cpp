#include <gtest/gtest.h>

#include <vector>

#include <ipv4.hpp>
#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetRawTcpHeader ) {
    const size_t ihl = 20;
    auto actual_header = ntk::get_raw_tcp_header( test_constants::tcp_syn_packet, ihl );
    std::vector<uint8_t> expected_header( std::begin( test_constants::tcp_syn_raw_tcp_header ), std::end( test_constants::tcp_syn_raw_tcp_header ) );
    ASSERT_EQ( actual_header, expected_header );
}