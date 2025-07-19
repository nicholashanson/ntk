#include <gtest/gtest.h>

#include <vector>
#include <iomanip>
#include <span>

#include <ipv4.hpp>
#include <tcp.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetParsedTcpHeader_SYN ) {
    std::vector<uint8_t> tcp_syn_raw_tcp_header( std::begin( test_constants::tcp_syn_raw_tcp_header ), std::end( test_constants::tcp_syn_raw_tcp_header ) );
    ntk::tcp_header actual_header = ntk::get_parsed_tcp_header( std::span<const uint8_t>( tcp_syn_raw_tcp_header ) );
    ASSERT_EQ( actual_header, test_constants::tcp_syn_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeader_SYNACK ) {
    std::vector<uint8_t> tcp_synack_raw_tcp_header( std::begin( test_constants::tcp_synack_raw_tcp_header ), std::end( test_constants::tcp_synack_raw_tcp_header ) );
    ntk::tcp_header actual_header = ntk::get_parsed_tcp_header( std::span<const uint8_t>( tcp_synack_raw_tcp_header ) );
    ASSERT_EQ( actual_header, test_constants::tcp_synack_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeader_ACK ) {
    std::vector<uint8_t> tcp_ack_raw_tcp_header( std::begin( test_constants::tcp_ack_raw_tcp_header ), std::end( test_constants::tcp_ack_raw_tcp_header ) );
    ntk::tcp_header actual_header = ntk::get_parsed_tcp_header( std::span<const uint8_t>( tcp_ack_raw_tcp_header ) );
    ASSERT_EQ( actual_header, test_constants::tcp_ack_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeader_EthernetFrameTcp ) {
    ntk::tcp_header actual_header = ntk::get_parsed_tcp_header( test::ethernet_frame_tcp );
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
    ASSERT_EQ( expected_header, actual_header );
}