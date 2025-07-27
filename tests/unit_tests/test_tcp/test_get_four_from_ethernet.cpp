#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetFourFromEthernet ) {
    ntk::four_tuple actual_four = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
    ntk::four_tuple expected_four = { 
        .client_ip = 0xc0a80014,
        .server_ip = 0xc0a80015,
        .client_port = 0xac18,
        .server_port = 0x0bb8
    };
    ASSERT_EQ( actual_four, expected_four );
}