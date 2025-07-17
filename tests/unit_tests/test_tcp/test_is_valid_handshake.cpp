#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <requests.hpp>
#include <io.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsValidHandshake ) {
    auto is_valid_handshake = ntk::is_valid_handshake( 
        test_constants::tcp_syn_parsed_tcp_header, 
        test_constants::tcp_synack_parsed_tcp_header, 
        test_constants::tcp_ack_parsed_tcp_header 
    );
    ASSERT_TRUE( is_valid_handshake );
}
