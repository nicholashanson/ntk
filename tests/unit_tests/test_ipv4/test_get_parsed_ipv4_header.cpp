#include <gtest/gtest.h>

#include <ipv4.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetParsedIpv4Header_TcpSyn ) {
    auto result = ntk::get_parsed_ipv4_header_from_ethernet( test_constants::tcp_syn_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
}

TEST( UnitTest, GetParsedIpv4Header_TcpSynAck ) {
    auto result = ntk::get_parsed_ipv4_header_from_ethernet( test_constants::tcp_synack_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
}

TEST( UnitTest, GetParsedIpv4Header_TcpSynPacket_ ) {
    auto raw_result = ntk::get_raw_ipv4_header( test_constants::tcp_syn_packet );
    ASSERT_TRUE( raw_result ) << raw_result.error() << std::endl;
    auto parsed_result = ntk::get_parsed_ipv4_header( raw_result.value() );
    ASSERT_TRUE( parsed_result ) << parsed_result.error() << std::endl;
    auto& parsed_ipv4_header = parsed_result.value();
    ASSERT_EQ( parsed_ipv4_header.protocol, static_cast<unsigned char>( ntk::protocol::tcp ) );
}