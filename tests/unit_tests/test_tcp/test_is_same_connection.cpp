#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsSameConnection ) {
    std::vector<uint8_t> tcp_syn_packet( std::begin( test_constants::tcp_syn_packet ), std::end( test_constants::tcp_syn_packet ) );
    std::vector<uint8_t> tcp_synack_packet( std::begin( test_constants::tcp_synack_packet ), std::end( test_constants::tcp_synack_packet ) );
    ASSERT_TRUE( ntk::is_same_connection( tcp_syn_packet, tcp_synack_packet ) );
}