#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetFourFromEthernet ) {
    ntk::four_tuple actual_four = *ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
    ntk::four_tuple expected_four = { 
        .src_ip = 0xc0a80014,
        .dest_ip = 0xc0a80015,
        .src_port = 0xac18,
        .dest_port = 0x0bb8
    };
    ASSERT_EQ( actual_four, expected_four );
}

TEST( UnitTest, GetFourFromEthernet_Syn ) {
    auto result = ntk::get_four_from_ethernet( test_constants::tcp_synack_packet );
    ASSERT_TRUE( result );
}



