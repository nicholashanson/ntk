#include <gtest/gtest.h>

#include <ipv4.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetRawIpv4Header_EthernetFrameUdp ) {
    auto ipv4_header = *ntk::get_raw_ipv4_header( test::ethernet_frame_udp );
    ASSERT_EQ( ipv4_header.size(), 20 );
}

TEST( UnitTest, GetRawIpv4Header_TcpSynPacket ) {
    auto actual_header = *ntk::get_raw_ipv4_header( test_constants::tcp_syn_packet );
    std::vector<uint8_t> expected_header( std::begin( test_constants::tcp_syn_ipv4_header ), std::end( test_constants::tcp_syn_ipv4_header ) );
    ASSERT_EQ( actual_header, expected_header );
}