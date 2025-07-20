#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, HasFlippedFour ) {
	auto four = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
	std::vector<uint8_t> tcp_synack_packet( std::begin( test_constants::tcp_synack_packet ), std::end( test_constants::tcp_synack_packet ) );
	ASSERT_TRUE( ntk::has_flipped_four( tcp_synack_packet, four ) );
}