#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsSameConnection_PacketPacket ) {
    auto result = ntk::is_same_connection( test_constants::tcp_syn_packet, test_constants::tcp_synack_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsSameConnection_PacketHeader ) {
    auto result = ntk::is_same_connection( test_constants::tcp_syn_packet, test_constants::tcp_synack_four );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsSameConnection_HeaderHeader ) {
    auto result = ntk::is_same_connection( test_constants::tcp_syn_four, test_constants::tcp_synack_four );
    ASSERT_TRUE( result );
}