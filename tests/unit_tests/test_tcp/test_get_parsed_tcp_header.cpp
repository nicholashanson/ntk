#include <gtest/gtest.h>

#include <vector>
#include <span>

#include <tcp.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetParsedTcpHeader_Syn ) {
    auto result = ntk::get_parsed_tcp_header( test_constants::tcp_syn_raw_tcp_header );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_syn_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeader_SynAck ) {
    auto result = ntk::get_parsed_tcp_header( test_constants::tcp_synack_raw_tcp_header );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_synack_parsed_tcp_header );
}

TEST( UnitTest, GetParsedTcpHeader_Ack ) {
    auto result = ntk::get_parsed_tcp_header( test_constants::tcp_ack_raw_tcp_header );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), test_constants::tcp_ack_parsed_tcp_header );
}