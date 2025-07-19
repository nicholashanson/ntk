#include <gtest/gtest.h>

#include <ipv4.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, ExtractIpv4Header_EthernetFrameUdp ) {
    std::vector<uint8_t> ipv4_header = ntk::get_raw_ipv4_header( test::ethernet_frame_udp );
    ASSERT_EQ( ipv4_header.size(), 20 );
}

TEST( UnitTest, ParseIpv4Header_TcpSynPacket ) {
    std::vector<uint8_t> ipv4_header = ntk::get_raw_ipv4_header( test_constants::tcp_syn_packet );
    ntk::ipv4_header header = ntk::get_parsed_ipv4_header( ipv4_header );
    ASSERT_EQ( header.protocol, static_cast<unsigned char>( ntk::protocol::TCP ) );
}