#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <requests.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsValidHandshake ) {
    auto is_valid_handshake = ntk::is_valid_handshake( 
        test_constants::tcp_syn_parsed_tcp_header, 
        test_constants::tcp_synack_parsed_tcp_header, 
        test_constants::tcp_ack_parsed_tcp_header 
    );
    ASSERT_TRUE( is_valid_handshake );
}

TEST( UnitTest, IsValidHandshake_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    const auto [ syn, synack, ack ] = std::array{ packet_data[ 0 ], packet_data[ 1 ], packet_data[ 2 ] };
    ASSERT_TRUE( ntk::is_valid_handshake( syn, synack, ack ) );
}