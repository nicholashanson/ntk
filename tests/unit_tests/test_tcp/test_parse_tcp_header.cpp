#include <gtest/gtest.h>

#include <vector>
#include <iomanip>

#include <ipv4.hpp>
#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, ParseTcpHeader_SYN ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_syn_raw_tcp_header );
    ASSERT_EQ( actual_header, test_constants::tcp_syn_parsed_tcp_header );
}

TEST( UnitTest, ParseTcpHeader_SYNACK ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_synack_raw_tcp_header );
    ASSERT_EQ( actual_header, test_constants::tcp_synack_parsed_tcp_header );
}

TEST( UnitTest, ParseTcpHeader_ACK ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_ack_raw_tcp_header );
    ASSERT_EQ( actual_header, test_constants::tcp_ack_parsed_tcp_header );
}