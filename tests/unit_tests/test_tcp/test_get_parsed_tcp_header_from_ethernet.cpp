#include <gtest/gtest.h>

#include <vector>
#include <span>

#include <tcp.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetParsedTcpHeaderFromEthernet_Syn ) {
    auto result = ntk::get_parsed_tcp_header_from_ethernet( test_constants::tcp_syn_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_syn_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeaderFromEthernet_SynAck ) {
    auto result = ntk::get_parsed_tcp_header_from_ethernet( test_constants::tcp_synack_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_synack_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeaderFromEthernet_Ack ) {
    auto result = ntk::get_parsed_tcp_header_from_ethernet( test_constants::tcp_ack_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_ack_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeaderFromEthernet_EthernetFrameTcp ) {
    auto result = ntk::get_parsed_tcp_header_from_ethernet( test::ethernet_frame_tcp );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ntk::tcp_header expected_header = {
        .src_port = 443,
        .dest_port = 52684,
        .seq_number = 0x9fa50857,
        .ack_number = 0x1d4203b7,
        .data_offset = 5,
        .window_size = 0x4002,
        .checksum = 0x952f,
        .urgent_ptr = 0
    };
    ASSERT_EQ( result.value(), expected_header );
}