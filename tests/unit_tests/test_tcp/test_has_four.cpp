#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, HasFour ) {
    auto four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
    ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
    std::vector<uint8_t> tcp_ack_packet( std::begin( test_constants::tcp_ack_packet ), std::end( test_constants::tcp_ack_packet ) );
    auto result = ntk::has_four( tcp_ack_packet, four_result.value() );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_TRUE( result.value() );
}

TEST( UnitTest, HasFour_CounterCase ) {
    auto four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
    ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
    std::vector<uint8_t> tcp_synack_packet( std::begin( test_constants::tcp_synack_packet ), std::end( test_constants::tcp_synack_packet ) );
    auto result = ntk::has_four( tcp_synack_packet, four_result.value() );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_FALSE( result.value() );
}
