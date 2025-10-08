#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetFourFromEthernet ) {
    auto four_result = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );
    ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
    ntk::four_tuple expected_four = { 
        .src_ip = 0xc0a80014,
        .dest_ip = 0xc0a80015,
        .src_port = 0xac18,
        .dest_port = 0x0bb8
    };
    ASSERT_EQ( four_result.value(), expected_four );
}

TEST( UnitTest, GetFourFromEthernet_Syn ) {
    auto result = ntk::get_four_from_ethernet( test_constants::tcp_synack_packet );
    ASSERT_TRUE( result );
}



